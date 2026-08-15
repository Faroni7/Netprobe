import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
} from '@mui/material';
import { Lock, Emergency } from '@mui/icons-material';
import { useAuthStore } from '../store';
import { apiService } from '../services/api';

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuthStore();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const tokenData = await apiService.login(username, password);
      const user = await apiService.getCurrentUser();
      login(user);
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        bgcolor: '#121212',
      }}
    >
      <Paper
        sx={{
          p: 4,
          width: '100%',
          maxWidth: 400,
          bgcolor: '#1e1e1e',
        }}
      >
        <Box display="flex" alignItems="center" justifyContent="center" mb={3}>
          <Lock sx={{ fontSize: 40, color: '#00bcd4', mr: 1 }} />
          <Typography variant="h4">NetSec Platform</Typography>
        </Box>

        <Alert severity="warning" sx={{ mb: 3 }}>
          <Box display="flex" alignItems="center">
            <Emergency sx={{ mr: 1 }} />
            Authorized Use Only
          </Box>
          <Typography variant="body2" sx={{ mt: 1 }}>
            This system is for authorized security testing and monitoring only.
            All activities are logged and audited.
          </Typography>
        </Alert>

        <form onSubmit={handleSubmit}>
          <TextField
            fullWidth
            label="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            margin="normal"
            required
            autoComplete="username"
          />
          <TextField
            fullWidth
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            margin="normal"
            required
            autoComplete="current-password"
          />

          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {error}
            </Alert>
          )}

          <Button
            type="submit"
            fullWidth
            variant="contained"
            size="large"
            disabled={loading}
            sx={{ mt: 3, mb: 2 }}
          >
            {loading ? 'Logging in...' : 'Login'}
          </Button>
        </form>
      </Paper>
    </Box>
  );
}
