"""
NetSec Platform - Kubernetes Network Visibility Module

Provides visibility into Kubernetes cluster networking including:
- Pod-to-pod flow correlation
- Service mesh traffic analysis
- Namespace isolation monitoring
- Container network interface tracking
- Kubernetes event correlation
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path

try:
    from kubernetes import client, config, watch
    from kubernetes.client.rest import ApiException
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False

from ..models.core_models import (
    NetworkFlow, IPAddress, MACAddress, TransportProtocol, 
    EncryptionState, SecurityFinding, FindingSeverity, FindingConfidence
)
from ..flow.flow_engine import FlowEngine
from ..utils.logging_config import get_logger

logger = get_logger(__name__)


class K8sResourceType(Enum):
    """Kubernetes resource types for tracking"""
    POD = "Pod"
    SERVICE = "Service"
    DEPLOYMENT = "Deployment"
    REPLICA_SET = "ReplicaSet"
    STATEFUL_SET = "StatefulSet"
    DAEMON_SET = "DaemonSet"
    JOB = "Job"
    CRON_JOB = "CronJob"
    CONFIG_MAP = "ConfigMap"
    SECRET = "Secret"
    INGRESS = "Ingress"
    NETWORK_POLICY = "NetworkPolicy"
    ENDPOINTS = "Endpoints"
    NODE = "Node"
    NAMESPACE = "Namespace"


class PodPhase(Enum):
    """Kubernetes pod phases"""
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    UNKNOWN = "Unknown"


class ServiceType(Enum):
    """Kubernetes service types"""
    CLUSTER_IP = "ClusterIP"
    NODE_PORT = "NodePort"
    LOAD_BALANCER = "LoadBalancer"
    EXTERNAL_NAME = "ExternalName"


@dataclass
class KubernetesPod:
    """Represents a Kubernetes pod with network information"""
    uid: str
    name: str
    namespace: str
    node_name: str
    phase: PodPhase
    pod_ip: Optional[str]
    host_ip: Optional[str]
    labels: Dict[str, str]
    annotations: Dict[str, str]
    containers: List[str]
    container_ips: List[str]
    service_account: str
    dns_policy: str
    dns_config: Optional[Dict[str, Any]]
    network_policies: List[str]
    first_seen: datetime
    last_seen: datetime
    deleted: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/serialization"""
        return {
            "uid": self.uid,
            "name": self.name,
            "namespace": self.namespace,
            "node_name": self.node_name,
            "phase": self.phase.value,
            "pod_ip": self.pod_ip,
            "host_ip": self.host_ip,
            "labels": self.labels,
            "annotations": self.annotations,
            "containers": self.containers,
            "container_ips": self.container_ips,
            "service_account": self.service_account,
            "dns_policy": self.dns_policy,
            "dns_config": self.dns_config,
            "network_policies": self.network_policies,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "deleted": self.deleted
        }


@dataclass
class KubernetesService:
    """Represents a Kubernetes service"""
    uid: str
    name: str
    namespace: str
    service_type: ServiceType
    cluster_ip: Optional[str]
    external_ips: List[str]
    ports: List[Dict[str, Any]]
    selector: Dict[str, str]
    endpoints: List[str]
    first_seen: datetime
    last_seen: datetime
    deleted: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "uid": self.uid,
            "name": self.name,
            "namespace": self.namespace,
            "service_type": self.service_type.value,
            "cluster_ip": self.cluster_ip,
            "external_ips": self.external_ips,
            "ports": self.ports,
            "selector": self.selector,
            "endpoints": self.endpoints,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "deleted": self.deleted
        }


@dataclass
class KubernetesNetworkPolicy:
    """Represents a Kubernetes NetworkPolicy"""
    uid: str
    name: str
    namespace: str
    pod_selector: Dict[str, str]
    policy_types: List[str]
    ingress_rules: List[Dict[str, Any]]
    egress_rules: List[Dict[str, Any]]
    first_seen: datetime
    last_seen: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "uid": self.uid,
            "name": self.name,
            "namespace": self.namespace,
            "pod_selector": self.pod_selector,
            "policy_types": self.policy_types,
            "ingress_rules": self.ingress_rules,
            "egress_rules": self.egress_rules,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat()
        }


@dataclass
class KubernetesFlow:
    """Enhanced flow with Kubernetes context"""
    flow: NetworkFlow
    src_pod: Optional[KubernetesPod]
    dst_pod: Optional[KubernetesPod]
    src_service: Optional[KubernetesService]
    dst_service: Optional[KubernetesService]
    src_namespace: str
    dst_namespace: str
    src_deployment: Optional[str]
    dst_deployment: Optional[str]
    network_policy_applied: bool
    policy_violation: bool
    service_mesh: bool
    cross_node: bool
    cross_namespace: bool
    findings: List[SecurityFinding] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "flow": self.flow.to_dict() if hasattr(self.flow, 'to_dict') else {},
            "src_pod": self.src_pod.to_dict() if self.src_pod else None,
            "dst_pod": self.dst_pod.to_dict() if self.dst_pod else None,
            "src_service": self.src_service.to_dict() if self.src_service else None,
            "dst_service": self.dst_service.to_dict() if self.dst_service else None,
            "src_namespace": self.src_namespace,
            "dst_namespace": self.dst_namespace,
            "src_deployment": self.src_deployment,
            "dst_deployment": self.dst_deployment,
            "network_policy_applied": self.network_policy_applied,
            "policy_violation": self.policy_violation,
            "service_mesh": self.service_mesh,
            "cross_node": self.cross_node,
            "cross_namespace": self.cross_namespace,
            "findings": [f.to_dict() if hasattr(f, 'to_dict') else {} for f in self.findings]
        }


class KubernetesWatcher:
    """Watches Kubernetes API for resource changes"""
    
    def __init__(self, kubeconfig_path: Optional[str] = None, context: Optional[str] = None):
        if not K8S_AVAILABLE:
            raise ImportError(
                "kubernetes library not installed. "
                "Install with: pip install kubernetes"
            )
        
        self.kubeconfig_path = kubeconfig_path
        self.context = context
        self.v1 = None
        self.networking_v1 = None
        self.apps_v1 = None
        self.watchers_running = False
        self.resource_cache: Dict[str, Dict[str, Any]] = {
            "pods": {},
            "services": {},
            "network_policies": {},
            "deployments": {},
            "nodes": {},
            "namespaces": {}
        }
        self.callbacks: Dict[str, List[callable]] = {
            "pod_added": [],
            "pod_modified": [],
            "pod_deleted": [],
            "service_added": [],
            "service_modified": [],
            "service_deleted": [],
            "policy_added": [],
            "policy_modified": [],
            "policy_deleted": []
        }
        
        logger.info("KubernetesWatcher initialized", extra={
            "kubeconfig_path": kubeconfig_path or "~/.kube/config",
            "context": context
        })
    
    def connect(self) -> bool:
        """Connect to Kubernetes cluster"""
        try:
            if self.kubeconfig_path:
                config.load_kube_config(config_file=self.kubeconfig_path, context=self.context)
            else:
                try:
                    config.load_incluster_config()
                    logger.info("Connected using in-cluster configuration")
                except config.ConfigException:
                    config.load_kube_config(context=self.context)
                    logger.info("Connected using kubeconfig")
            
            self.v1 = client.CoreV1Api()
            self.networking_v1 = client.NetworkingV1Api()
            self.apps_v1 = client.AppsV1Api()
            
            version = self.v1.get_code()
            logger.info("Connected to Kubernetes cluster", extra={
                "version": f"{version.major}.{version.minor}",
                "platform": version.platform
            })
            
            return True
            
        except Exception as e:
            logger.error("Failed to connect to Kubernetes cluster", extra={
                "error": str(e),
                "kubeconfig_path": self.kubeconfig_path
            })
            return False
    
    def register_callback(self, event_type: str, callback: callable):
        """Register callback for resource events"""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
            logger.debug("Registered callback for event", extra={"event_type": event_type})
    
    async def _trigger_callback(self, event_type: str, resource: Any):
        """Trigger callbacks for an event"""
        for callback in self.callbacks.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(resource)
                else:
                    callback(resource)
            except Exception as e:
                logger.error("Callback execution failed", extra={
                    "event_type": event_type,
                    "error": str(e)
                })
    
    async def watch_pods(self, namespace: Optional[str] = None):
        """Watch for pod changes"""
        if not self.v1:
            logger.error("Not connected to Kubernetes cluster")
            return
        
        logger.info("Starting pod watcher", extra={"namespace": namespace or "all"})
        
        try:
            w = watch.Watch()
            for event in w.stream(
                self.v1.list_pod_for_all_namespaces,
                timeout_seconds=300
            ):
                event_type = event['type']
                pod_data = event['object']
                
                pod = self._parse_pod(pod_data)
                
                if event_type == 'ADDED':
                    self.resource_cache["pods"][pod.uid] = pod
                    await self._trigger_callback("pod_added", pod)
                elif event_type == 'MODIFIED':
                    old_pod = self.resource_cache["pods"].get(pod.uid)
                    self.resource_cache["pods"][pod.uid] = pod
                    await self._trigger_callback("pod_modified", pod)
                elif event_type == 'DELETED':
                    if pod.uid in self.resource_cache["pods"]:
                        pod.deleted = True
                        self.resource_cache["pods"][pod.uid] = pod
                        await self._trigger_callback("pod_deleted", pod)
                        
        except ApiException as e:
            logger.error("Kubernetes API error while watching pods", extra={
                "status": e.status,
                "reason": e.reason
            })
        except Exception as e:
            logger.error("Error watching pods", extra={"error": str(e)})
    
    async def watch_services(self, namespace: Optional[str] = None):
        """Watch for service changes"""
        if not self.v1:
            return
        
        logger.info("Starting service watcher", extra={"namespace": namespace or "all"})
        
        try:
            w = watch.Watch()
            for event in w.stream(
                self.v1.list_service_for_all_namespaces,
                timeout_seconds=300
            ):
                event_type = event['type']
                svc_data = event['object']
                
                service = self._parse_service(svc_data)
                
                if event_type == 'ADDED':
                    self.resource_cache["services"][service.uid] = service
                    await self._trigger_callback("service_added", service)
                elif event_type == 'MODIFIED':
                    self.resource_cache["services"][service.uid] = service
                    await self._trigger_callback("service_modified", service)
                elif event_type == 'DELETED':
                    if service.uid in self.resource_cache["services"]:
                        service.deleted = True
                        self.resource_cache["services"][service.uid] = service
                        await self._trigger_callback("service_deleted", service)
                        
        except Exception as e:
            logger.error("Error watching services", extra={"error": str(e)})
    
    async def watch_network_policies(self, namespace: Optional[str] = None):
        """Watch for network policy changes"""
        if not self.networking_v1:
            return
        
        logger.info("Starting network policy watcher", extra={"namespace": namespace or "all"})
        
        try:
            w = watch.Watch()
            for event in w.stream(
                self.networking_v1.list_network_policy_for_all_namespaces,
                timeout_seconds=300
            ):
                event_type = event['type']
                policy_data = event['object']
                
                policy = self._parse_network_policy(policy_data)
                
                if event_type == 'ADDED':
                    self.resource_cache["network_policies"][policy.uid] = policy
                    await self._trigger_callback("policy_added", policy)
                elif event_type == 'MODIFIED':
                    self.resource_cache["network_policies"][policy.uid] = policy
                    await self._trigger_callback("policy_modified", policy)
                elif event_type == 'DELETED':
                    if policy.uid in self.resource_cache["network_policies"]:
                        self.resource_cache["network_policies"][policy.uid] = policy
                        await self._trigger_callback("policy_deleted", policy)
                        
        except Exception as e:
            logger.error("Error watching network policies", extra={"error": str(e)})
    
    def _parse_pod(self, pod_data) -> KubernetesPod:
        """Parse Kubernetes pod object"""
        metadata = pod_data.metadata
        spec = pod_data.spec
        status = pod_data.status
        
        containers = [c.name for c in spec.containers] if spec.containers else []
        pod_ip = status.pod_ip if status else None
        
        return KubernetesPod(
            uid=str(metadata.uid),
            name=metadata.name,
            namespace=metadata.namespace,
            node_name=spec.node_name,
            phase=PodPhase(status.phase) if status.phase else PodPhase.UNKNOWN,
            pod_ip=pod_ip,
            host_ip=status.host_ip if status else None,
            labels=dict(metadata.labels) if metadata.labels else {},
            annotations=dict(metadata.annotations) if metadata.annotations else {},
            containers=containers,
            container_ips=[],
            service_account=spec.service_account_name or "default",
            dns_policy=spec.dns_policy,
            dns_config=None,
            network_policies=[],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
    
    def _parse_service(self, svc_data) -> KubernetesService:
        """Parse Kubernetes service object"""
        metadata = svc_data.metadata
        spec = svc_data.spec
        
        ports = []
        if spec.ports:
            for port in spec.ports:
                ports.append({
                    "name": port.name,
                    "port": port.port,
                    "target_port": port.target_port,
                    "protocol": port.protocol
                })
        
        svc_type = ServiceType.CLUSTER_IP
        if spec.type:
            try:
                svc_type = ServiceType(spec.type)
            except ValueError:
                pass
        
        return KubernetesService(
            uid=str(metadata.uid),
            name=metadata.name,
            namespace=metadata.namespace,
            service_type=svc_type,
            cluster_ip=spec.cluster_ip,
            external_ips=spec.external_ips or [],
            ports=ports,
            selector=dict(spec.selector) if spec.selector else {},
            endpoints=[],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
    
    def _parse_network_policy(self, policy_data) -> KubernetesNetworkPolicy:
        """Parse Kubernetes NetworkPolicy object"""
        metadata = policy_data.metadata
        spec = policy_data.spec
        
        pod_selector = {}
        if spec.pod_selector and spec.pod_selector.match_labels:
            pod_selector = dict(spec.pod_selector.match_labels)
        
        policy_types = spec.policy_types or []
        
        ingress_rules = []
        if spec.ingress:
            for rule in spec.ingress:
                ingress_rules.append({"from": [], "to": [], "ports": []})
        
        egress_rules = []
        if spec.egress:
            for rule in spec.egress:
                egress_rules.append({"from": [], "to": [], "ports": []})
        
        return KubernetesNetworkPolicy(
            uid=str(metadata.uid),
            name=metadata.name,
            namespace=metadata.namespace,
            pod_selector=pod_selector,
            policy_types=policy_types,
            ingress_rules=ingress_rules,
            egress_rules=egress_rules,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
    
    def get_pod_by_ip(self, ip: str) -> Optional[KubernetesPod]:
        """Find pod by IP address"""
        for pod in self.resource_cache["pods"].values():
            if pod.pod_ip == ip and not pod.deleted:
                return pod
        return None
    
    def get_service_by_cluster_ip(self, ip: str) -> Optional[KubernetesService]:
        """Find service by ClusterIP"""
        for svc in self.resource_cache["services"].values():
            if svc.cluster_ip == ip and not svc.deleted:
                return svc
        return None
    
    def get_pods_by_namespace(self, namespace: str) -> List[KubernetesPod]:
        """Get all pods in a namespace"""
        return [
            pod for pod in self.resource_cache["pods"].values()
            if pod.namespace == namespace and not pod.deleted
        ]
    
    def get_applicable_policies(self, pod: KubernetesPod) -> List[KubernetesNetworkPolicy]:
        """Get network policies that apply to a pod"""
        applicable = []
        
        for policy in self.resource_cache["network_policies"].values():
            if policy.namespace != pod.namespace:
                continue
            
            if not policy.pod_selector:
                applicable.append(policy)
                continue
            
            matches = all(
                pod.labels.get(key) == value
                for key, value in policy.pod_selector.items()
            )
            if matches:
                applicable.append(policy)
        
        return applicable
    
    def start_watching(self, namespaces: Optional[List[str]] = None):
        """Start all watchers"""
        if not self.connect():
            return
        
        self.watchers_running = True
        asyncio.create_task(self.watch_pods())
        asyncio.create_task(self.watch_services())
        asyncio.create_task(self.watch_network_policies())
        
        logger.info("Kubernetes watchers started", extra={"namespaces": namespaces or "all"})
    
    def stop_watching(self):
        """Stop all watchers"""
        self.watchers_running = False
        logger.info("Kubernetes watchers stopped")
    
    def get_cluster_summary(self) -> Dict[str, Any]:
        """Get summary of cluster state"""
        active_pods = [p for p in self.resource_cache["pods"].values() if not p.deleted]
        active_services = [s for s in self.resource_cache["services"].values() if not s.deleted]
        active_policies = list(self.resource_cache["network_policies"].values())
        
        namespaces = set(p.namespace for p in active_pods)
        
        return {
            "total_pods": len(active_pods),
            "total_services": len(active_services),
            "total_network_policies": len(active_policies),
            "namespaces": list(namespaces),
            "pods_by_namespace": {
                ns: len([p for p in active_pods if p.namespace == ns])
                for ns in namespaces
            },
            "pods_by_phase": {
                phase.value: len([p for p in active_pods if p.phase == phase])
                for phase in PodPhase
            }
        }


class KubernetesFlowCorrelator:
    """Correlates network flows with Kubernetes resources"""
    
    def __init__(self, watcher: KubernetesWatcher, flow_engine: FlowEngine):
        self.watcher = watcher
        self.flow_engine = flow_engine
        self.correlated_flows: Dict[str, KubernetesFlow] = {}
        self.findings: List[SecurityFinding] = []
        
        logger.info("KubernetesFlowCorrelator initialized")
    
    async def correlate_flow(self, flow: NetworkFlow) -> Optional[KubernetesFlow]:
        """Correlate a network flow with Kubernetes resources"""
        src_pod = None
        dst_pod = None
        src_service = None
        dst_service = None
        
        if flow.src_ip:
            src_pod = self.watcher.get_pod_by_ip(str(flow.src_ip))
            if not src_pod:
                src_service = self.watcher.get_service_by_cluster_ip(str(flow.src_ip))
        
        if flow.dst_ip:
            dst_pod = self.watcher.get_pod_by_ip(str(flow.dst_ip))
            if not dst_pod:
                dst_service = self.watcher.get_service_by_cluster_ip(str(flow.dst_ip))
        
        if not (src_pod or dst_pod or src_service or dst_service):
            return None
        
        src_namespace = (src_pod or src_service).namespace if (src_pod or src_service) else "unknown"
        dst_namespace = (dst_pod or dst_service).namespace if (dst_pod or dst_service) else "unknown"
        
        src_deployment = self._get_deployment_from_pod(src_pod) if src_pod else None
        dst_deployment = self._get_deployment_from_pod(dst_pod) if dst_pod else None
        
        cross_namespace = src_namespace != dst_namespace
        
        cross_node = False
        if src_pod and dst_pod and src_pod.node_name and dst_pod.node_name:
            cross_node = src_pod.node_name != dst_pod.node_name
        
        policies_violated = []
        if src_pod:
            src_policies = self.watcher.get_applicable_policies(src_pod)
            for policy in src_policies:
                if self._check_policy_violation(policy, flow, is_egress=True):
                    policies_violated.append(policy.name)
        
        policy_violation = len(policies_violated) > 0
        service_mesh = self._detect_service_mesh(flow)
        
        k8s_flow = KubernetesFlow(
            flow=flow,
            src_pod=src_pod,
            dst_pod=dst_pod,
            src_service=src_service,
            dst_service=dst_service,
            src_namespace=src_namespace,
            dst_namespace=dst_namespace,
            src_deployment=src_deployment,
            dst_deployment=dst_deployment,
            network_policy_applied=len(self.watcher.get_applicable_policies(src_pod or dst_pod)) > 0 if (src_pod or dst_pod) else False,
            policy_violation=policy_violation,
            service_mesh=service_mesh,
            cross_node=cross_node,
            cross_namespace=cross_namespace
        )
        
        if policy_violation:
            finding = SecurityFinding(
                title="Kubernetes Network Policy Violation",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                description=f"Traffic detected that violates network policy: {', '.join(policies_violated)}",
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                proto=flow.proto,
                evidence_references=[],
                remediation="Review and update NetworkPolicy rules"
            )
            k8s_flow.findings.append(finding)
            self.findings.append(finding)
        
        self.correlated_flows[f"{flow.fid}"] = k8s_flow
        return k8s_flow
    
    def _get_deployment_from_pod(self, pod: KubernetesPod) -> Optional[str]:
        """Extract deployment name from pod labels"""
        if not pod:
            return None
        
        deployment_labels = ['app.kubernetes.io/instance', 'app', 'deployment']
        for label in deployment_labels:
            if label in pod.labels:
                return pod.labels[label]
        
        return None
    
    def _check_policy_violation(self, policy: KubernetesNetworkPolicy, flow: NetworkFlow, is_egress: bool) -> bool:
        """Check if a flow violates a network policy"""
        rules = policy.egress_rules if is_egress else policy.ingress_rules
        
        if not rules and (policy.policy_types and ("Egress" if is_egress else "Ingress") in policy.policy_types):
            return True
        
        return len(rules) > 0
    
    def _detect_service_mesh(self, flow: NetworkFlow) -> bool:
        """Detect if flow is part of a service mesh"""
        service_mesh_ports = {15001, 15006, 15011, 15021, 4191, 4291}
        return flow.dst_port in service_mesh_ports or flow.src_port in service_mesh_ports
    
    def get_flows_by_namespace(self, namespace: str) -> List[KubernetesFlow]:
        """Get all flows involving a namespace"""
        return [
            flow for flow in self.correlated_flows.values()
            if flow.src_namespace == namespace or flow.dst_namespace == namespace
        ]
    
    def get_policy_violations(self) -> List[KubernetesFlow]:
        """Get all flows with policy violations"""
        return [flow for flow in self.correlated_flows.values() if flow.policy_violation]
    
    def get_findings(self) -> List[SecurityFinding]:
        """Get all security findings from correlation"""
        return self.findings.copy()
