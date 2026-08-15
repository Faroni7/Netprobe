"""
Packet Capture Engine.

Provides live packet capture, PCAP import/export, and capture management.
Uses scapy for mature packet capture functionality.
"""

import os
import time
import threading
import logging
from enum import Enum
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from pathlib import Path
from queue import Queue, Full, Empty
import hashlib

try:
    from scapy.all import (
        sniff,
        get_if_list,
        get_if_hwaddr,
        wrpcap,
        rdpcap,
        Packet,
        RawPcapReader,
        RawPcapWriter,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from netsec_platform.models.core_models import RawPacket, DecodedPacket
from netsec_platform.config.settings import NetSecConfig, CaptureProfileEnum


logger = logging.getLogger(__name__)


class CaptureStatus(str, Enum):
    """Capture engine status."""
    IDLE = "idle"
    STARTING = "starting"
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class CaptureStats:
    """Capture statistics."""
    packets_captured: int = 0
    packets_dropped: int = 0
    bytes_captured: int = 0
    capture_rate: float = 0.0  # packets per second
    processing_rate: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    interface: Optional[str] = None
    filter_expression: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "packets_captured": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "bytes_captured": self.bytes_captured,
            "capture_rate": round(self.capture_rate, 2),
            "processing_rate": round(self.processing_rate, 2),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "interface": self.interface,
            "filter_expression": self.filter_expression,
        }


@dataclass
class CaptureConfig:
    """Configuration for a capture session."""
    interface: str
    snaplen: int = 65535
    capture_filter: Optional[str] = None
    max_packets: Optional[int] = None
    max_bytes: Optional[int] = None
    max_duration_seconds: Optional[int] = None
    profile: CaptureProfileEnum = CaptureProfileEnum.STANDARD
    store_payloads: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "interface": self.interface,
            "snaplen": self.snaplen,
            "capture_filter": self.capture_filter,
            "max_packets": self.max_packets,
            "max_bytes": self.max_bytes,
            "max_duration_seconds": self.max_duration_seconds,
            "profile": self.profile.value,
            "store_payloads": self.store_payloads,
        }


class PacketCaptureEngine:
    """
    Packet capture engine.
    
    Provides:
    - Live packet capture from interfaces
    - PCAP/PCAPNG import/export
    - Capture statistics and health monitoring
    - Backpressure handling with bounded queues
    - Emergency stop integration
    """
    
    def __init__(
        self,
        settings: NetSecConfig,
        packet_queue_size: int = 10000,
    ):
        self.settings = settings
        self.status = CaptureStatus.IDLE
        self.config: Optional[CaptureConfig] = None
        self.stats = CaptureStats()
        
        # Bounded queue for backpressure
        self.packet_queue: Queue[RawPacket] = Queue(maxsize=packet_queue_size)
        self.dropped_packets = 0
        
        # Capture thread
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        
        # Callbacks
        self._packet_callback: Optional[Callable[[RawPacket], None]] = None
        self._emergency_stop_callback: Optional[Callable[[], None]] = None
        
        # Interface cache
        self._interfaces: Optional[List[Dict[str, Any]]] = None
        self._last_interface_refresh = 0.0
        
        logger.info("PacketCaptureEngine initialized")
    
    def discover_interfaces(self) -> List[Dict[str, Any]]:
        """Discover available network interfaces."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, returning empty interface list")
            return []
        
        try:
            interfaces = []
            for iface in get_if_list():
                try:
                    mac = get_if_hwaddr(iface)
                except Exception:
                    mac = None
                
                interfaces.append({
                    "name": iface,
                    "mac": mac,
                    "description": f"Interface {iface}",
                })
            
            self._interfaces = interfaces
            self._last_interface_refresh = time.time()
            return interfaces
        except Exception as e:
            logger.error(f"Error discovering interfaces: {e}")
            return []
    
    def set_packet_callback(self, callback: Callable[[RawPacket], None]):
        """Set callback for processed packets."""
        self._packet_callback = callback
    
    def set_emergency_stop_callback(self, callback: Callable[[], None]):
        """Set callback for emergency stop requests."""
        self._emergency_stop_callback = callback
    
    def start_capture(self, config: CaptureConfig) -> bool:
        """Start packet capture with the given configuration."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available, cannot start capture")
            self.status = CaptureStatus.ERROR
            return False
        
        with self._lock:
            if self.status == CaptureStatus.ACTIVE:
                logger.warning("Capture already active")
                return False
            
            self.config = config
            self.status = CaptureStatus.STARTING
            self.stats = CaptureStats(
                start_time=datetime.now(timezone.utc),
                interface=config.interface,
                filter_expression=config.capture_filter,
            )
            self._stop_event.clear()
            self.dropped_packets = 0
        
        logger.info(f"Starting capture on {config.interface}")
        
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            name="PacketCaptureThread",
            daemon=True,
        )
        self._capture_thread.start()
        
        return True
    
    def _capture_loop(self):
        """Main capture loop running in separate thread."""
        if not self.config:
            return
        
        try:
            def packet_handler(pkt: Packet):
                if self._stop_event.is_set():
                    return
                
                # Check limits
                if self.config.max_packets and self.stats.packets_captured >= self.config.max_packets:
                    self._request_emergency_stop("Max packets reached")
                    return
                
                if self.config.max_bytes and self.stats.bytes_captured >= self.config.max_bytes:
                    self._request_emergency_stop("Max bytes reached")
                    return
                
                # Convert to RawPacket
                raw_data = bytes(pkt)
                raw_pkt = RawPacket(
                    packet_id=self.stats.packets_captured,
                    timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
                    interface=self.config.interface,
                    data=raw_data if self.config.store_payloads else b"",
                    captured_length=len(raw_data),
                    original_length=len(pkt),
                )
                
                # Update stats
                self.stats.packets_captured += 1
                self.stats.bytes_captured += len(raw_data)
                
                # Try to queue packet (backpressure)
                try:
                    self.packet_queue.put_nowait(raw_pkt)
                except Full:
                    self.dropped_packets += 1
                    self.stats.packets_dropped += 1
                    logger.debug("Packet queue full, dropping packet")
                
                # Call packet callback
                if self._packet_callback:
                    try:
                        self._packet_callback(raw_pkt)
                    except Exception as e:
                        logger.error(f"Packet callback error: {e}")
            
            # Calculate timeout for duration limit
            timeout = None
            if self.config.max_duration_seconds:
                timeout = self.config.max_duration_seconds
            
            # Start capture
            self.status = CaptureStatus.ACTIVE
            
            sniff(
                iface=self.config.interface,
                prn=packet_handler,
                store=False,
                snf_filter=self.config.capture_filter,
                timeout=timeout,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
            
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.status = CaptureStatus.ERROR
        finally:
            self.status = CaptureStatus.STOPPED
            self.stats.end_time = datetime.now(timezone.utc)
            logger.info(f"Capture stopped. Captured {self.stats.packets_captured} packets")
    
    def _request_emergency_stop(self, reason: str):
        """Request emergency stop."""
        logger.warning(f"Emergency stop requested: {reason}")
        self._stop_event.set()
        if self._emergency_stop_callback:
            try:
                self._emergency_stop_callback()
            except Exception as e:
                logger.error(f"Emergency stop callback error: {e}")
    
    def stop_capture(self):
        """Stop packet capture."""
        logger.info("Stopping capture")
        self._stop_event.set()
        self.status = CaptureStatus.STOPPING
        
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5.0)
        
        self.status = CaptureStatus.STOPPED
        self.stats.end_time = datetime.now(timezone.utc)
    
    def get_stats(self) -> CaptureStats:
        """Get current capture statistics."""
        # Calculate rates
        if self.stats.start_time:
            elapsed = (datetime.now(timezone.utc) - self.stats.start_time).total_seconds()
            if elapsed > 0:
                self.stats.capture_rate = self.stats.packets_captured / elapsed
        
        # Add dropped packets from queue overflow
        self.stats.packets_dropped = self.dropped_packets
        
        return self.stats
    
    def is_healthy(self) -> bool:
        """Check if capture is healthy."""
        if self.status != CaptureStatus.ACTIVE:
            return False
        
        stats = self.get_stats()
        drop_rate = stats.packets_dropped / max(stats.packets_captured, 1)
        
        # Consider unhealthy if drop rate > 10%
        return drop_rate < 0.10
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get detailed health status."""
        stats = self.get_stats()
        drop_rate = stats.packets_dropped / max(stats.packets_captured, 1) * 100
        
        return {
            "status": self.status.value,
            "captured": stats.packets_captured,
            "dropped": stats.packets_dropped,
            "drop_rate_percent": round(drop_rate, 2),
            "bytes_captured": stats.bytes_captured,
            "capture_rate": round(stats.capture_rate, 2),
            "healthy": self.is_healthy(),
            "queue_size": self.packet_queue.qsize(),
            "queue_max": self.packet_queue.maxsize,
        }


class PCAPHandler:
    """
    PCAP/PCAPNG file handler.
    
    Provides import/export functionality for packet capture files.
    """
    
    def __init__(self, storage_path: str):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"PCAPHandler initialized with storage path: {self.storage_path}")
    
    def export_pcap(
        self,
        packets: List[RawPacket],
        filename: Optional[str] = None,
        pcapng: bool = False,
    ) -> Optional[str]:
        """Export packets to PCAP/PCAPNG file."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available for PCAP export")
            return None
        
        if not packets:
            logger.warning("No packets to export")
            return None
        
        try:
            if filename is None:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                ext = "pcapng" if pcapng else "pcap"
                filename = f"capture_{timestamp}.{ext}"
            
            filepath = self.storage_path / filename
            
            # Convert to scapy packets
            from scapy.all import Ether
            
            scapy_packets = []
            for pkt in packets:
                if pkt.data:
                    try:
                        scapy_pkt = Ether(pkt.data)
                        scapy_pkt.time = pkt.timestamp.timestamp()
                        scapy_packets.append(scapy_pkt)
                    except Exception as e:
                        logger.warning(f"Failed to convert packet: {e}")
            
            if not scapy_packets:
                logger.warning("No valid packets to write")
                return None
            
            # Write to file
            if pcapng:
                # Use RawPcapWriter for PCAPNG
                with RawPcapWriter(str(filepath)) as writer:
                    for pkt in scapy_packets:
                        writer.write(bytes(pkt))
            else:
                wrpcap(str(filepath), scapy_packets)
            
            logger.info(f"Exported {len(scapy_packets)} packets to {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"PCAP export error: {e}")
            return None
    
    def import_pcap(self, filepath: str) -> List[RawPacket]:
        """Import packets from PCAP/PCAPNG file."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available for PCAP import")
            return []
        
        try:
            path = Path(filepath)
            if not path.exists():
                logger.error(f"PCAP file not found: {filepath}")
                return []
            
            packets = []
            scapy_packets = rdpcap(str(path))
            
            for i, pkt in enumerate(scapy_packets):
                raw_data = bytes(pkt)
                raw_pkt = RawPacket(
                    packet_id=i,
                    timestamp=datetime.fromtimestamp(float(pkt.time), tz=timezone.utc),
                    interface="import",
                    data=raw_data,
                    captured_length=len(raw_data),
                    original_length=len(raw_data),
                )
                packets.append(raw_pkt)
            
            logger.info(f"Imported {len(packets)} packets from {filepath}")
            return packets
            
        except Exception as e:
            logger.error(f"PCAP import error: {e}")
            return []
    
    def calculate_hash(self, filepath: str) -> Optional[str]:
        """Calculate SHA-256 hash of a PCAP file for integrity verification."""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation error: {e}")
            return None
