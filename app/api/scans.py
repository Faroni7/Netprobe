"""
BlackBox Recon - Scans API Router
Scan management and execution
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.db import get_db
from app.models import Scan, Target
from app.schemas import ScanCreate, ScanResponse
from app.recon.pipeline import ReconPipeline

router = APIRouter(prefix="/scans", tags=["scans"])


async def run_scan_pipeline(scan_id: int, target_url: str, db: AsyncSession):
    """Run the reconnaissance pipeline in background."""
    try:
        pipeline = ReconPipeline(target_url, scan_id, db)
        result = await pipeline.run()
        return result
    except Exception as e:
        # Update scan status on error
        from sqlalchemy import update
        await db.execute(
            update(Scan).where(Scan.id == scan_id).values(
                status="failed",
                error_message=str(e),
                completed_at=None  # Will be set by pipeline
            )
        )
        await db.commit()
        raise


@router.get("", response_model=List[ScanResponse])
async def list_scans(db: AsyncSession = Depends(get_db)):
    """List all scans."""
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(scan: ScanCreate, db: AsyncSession = Depends(get_db)):
    """Create a new scan for a target."""
    # Verify target exists
    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()
    
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )
    
    db_scan = Scan(target_id=scan.target_id, status="pending")
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)
    return db_scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific scan by ID."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return scan


@router.post("/{scan_id}/start", response_model=ScanResponse)
async def start_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Start a scan execution."""
    # Get scan with target info
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status == "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan is already running"
        )
    
    # Get target URL
    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()
    
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )
    
    # Start scan in background
    background_tasks.add_task(run_scan_pipeline, scan_id, target.url, db)
    
    # Update status to running
    from sqlalchemy import update
    from datetime import datetime
    await db.execute(
        update(Scan).where(Scan.id == scan_id).values(
            status="running",
            started_at=datetime.now()
        )
    )
    await db.commit()
    
    # Refresh and return
    await db.refresh(scan)
    return scan


@router.post("/{scan_id}/stop", response_model=ScanResponse)
async def stop_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Request stop of a running scan."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status != "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan is not running"
        )
    
    # Update status - pipeline will check this
    from sqlalchemy import update
    await db.execute(
        update(Scan).where(Scan.id == scan_id).values(status="stopping")
    )
    await db.commit()
    await db.refresh(scan)
    
    return scan


@router.get("/{scan_id}/events", response_model=List[dict])
async def get_scan_events(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get all events for a scan."""
    from app.models import ScanEvent
    from sqlalchemy import select
    
    # Verify scan exists
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    events_result = await db.execute(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.phase_order, ScanEvent.created_at)
    )
    events = events_result.scalars().all()
    
    return [
        {
            "id": e.id,
            "scan_id": e.scan_id,
            "phase_name": e.phase_name,
            "phase_order": e.phase_order,
            "status": e.status,
            "result_data": e.result_data,
            "error_message": e.error_message,
            "created_at": e.created_at
        }
        for e in events
    ]
