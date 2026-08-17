import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  Alert,
  Checkbox,
  FormControlLabel,
  TextField,
} from '@mui/material';
import { Emergency, Warning } from '@mui/icons-material';
import { useCaptureStore } from '../store';
import { apiService } from '../services/api';

interface EmergencyStopDialogProps {
  open: boolean;
  onClose: () => void;
}

export default function EmergencyStopDialog({ open, onClose }: EmergencyStopDialogProps) {
  const [stopCapture, setStopCapture] = useState(true);
  const [stopProcessing, setStopProcessing] = useState(true);
  const [stopTests, setStopTests] = useState(true);
  const [stopExports, setStopExports] = useState(true);
  const [lockSensitive, setLockSensitive] = useState(true);
  const [reason, setReason] = useState('');
  const [isActivating, setIsActivating] = useState(false);
  const { activateESS, setESSStatus } = useCaptureStore();

  const handleActivate = async () => {
    if (!reason.trim()) {
      alert('Please provide a reason for the emergency stop');
      return;
    }

    setIsActivating(true);
    try {
      activateESS();
      await apiService.activateESS(reason);
      setESSStatus({
        state: 'STOPPED',
        enabled: true,
        activated_at: new Date().toISOString(),
        reason,
      });
      onClose();
    } catch (error) {
      console.error('Failed to activate ESS:', error);
    } finally {
      setIsActivating(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ bgcolor: '#f44336', color: 'white' }}>
        <Box display="flex" alignItems="center" gap={1}>
          <Emergency />
          EMERGENCY SECURITY STOP
        </Box>
      </DialogTitle>
      <DialogContent sx={{ mt: 2 }}>
        <Alert severity="warning" sx={{ mb: 2 }}>
          <Typography variant="body2">
            This will immediately stop all security-sensitive operations. 
            Evidence will be preserved and sensitive data will be locked.
          </Typography>
        </Alert>

        <Box sx={{ ml: 2 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={stopCapture}
                onChange={(e) => setStopCapture(e.target.checked)}
              />
            }
            label="Stop packet capture"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={stopProcessing}
                onChange={(e) => setStopProcessing(e.target.checked)}
              />
            }
            label="Stop packet processing"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={stopTests}
                onChange={(e) => setStopTests(e.target.checked)}
              />
            }
            label="Stop active security tests"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={stopExports}
                onChange={(e) => setStopExports(e.target.checked)}
              />
            }
            label="Stop exports"
          />
          <FormControlLabel
            control={
              <Checkbox
                checked={lockSensitive}
                onChange={(e) => setLockSensitive(e.target.checked)}
              />
            }
            label="Lock sensitive evidence access"
          />
        </Box>

        <TextField
          fullWidth
          multiline
          rows={3}
          label="Reason for Emergency Stop"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          sx={{ mt: 2 }}
          required
        />

        <Alert severity="info" sx={{ mt: 2 }}>
          <Typography variant="body2">
            <Warning sx={{ verticalAlign: 'middle', mr: 0.5 }} />
            After activation, the system will remain in a locked state until 
            an authorized operator performs recovery.
          </Typography>
        </Alert>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={isActivating}>
          Cancel
        </Button>
        <Button
          onClick={handleActivate}
          variant="contained"
          color="error"
          disabled={isActivating || !reason.trim()}
        >
          {isActivating ? 'Activating...' : 'CONFIRM EMERGENCY STOP'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
