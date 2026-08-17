import { useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Chip,
} from '@mui/material';
import {
  NetworkCheck,
  Security,
  Warning,
  Dns,
  Lock,
  LockOpen,
} from '@mui/icons-material';
import { useDataStore, useCaptureStore } from '../store';
import { apiService } from '../services/api';
import TrafficChart from '../components/TrafficChart';
import StatCard from '../components/StatCard';

export default function Dashboard() {
  const { dashboardStats, setDashboardStats } = useDataStore();
  const { status, setCaptureStatus, essStatus, setESSStatus } = useCaptureStore();

  useEffect(() => {
    // Load dashboard stats
    apiService.getDashboardStats()
      .then(setDashboardStats)
      .catch(console.error);

    // Load capture status
    apiService.getCaptureStatus()
      .then(setCaptureStatus)
      .catch(console.error);

    // Load ESS status
    apiService.getESSStatus()
      .then(setESSStatus)
      .catch(console.error);
  }, [setDashboardStats, setCaptureStatus, setESSStatus]);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>

      {/* Capture Status */}
      {status && (
        <Paper sx={{ p: 2, mb: 3, bgcolor: '#1e1e1e' }}>
          <Box display="flex" justifyContent="space-between" alignItems="center">
            <Box>
              <Typography variant="h6">
                Capture Status: {status.status}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Interface: {status.interface} | 
                Profile: {status.profile} | 
                Packets: {status.packets_captured.toLocaleString()}
              </Typography>
            </Box>
            <Chip
              label={`Drop Rate: ${(status.drop_rate * 100).toFixed(2)}%`}
              color={status.drop_rate > 0.05 ? 'error' : 'success'}
            />
          </Box>
        </Paper>
      )}

      {/* ESS Status Alert */}
      {essStatus?.state === 'STOPPED' && (
        <Paper sx={{ p: 2, mb: 3, bgcolor: '#f44336', color: 'white' }}>
          <Typography variant="h6">
            ⚠️ EMERGENCY SECURITY STOP ACTIVATED
          </Typography>
          <Typography variant="body2">
            Reason: {essStatus.reason} | 
            Time: {essStatus.activated_at ? new Date(essStatus.activated_at).toLocaleString() : 'Unknown'}
          </Typography>
        </Paper>
      )}

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Flows"
            value={dashboardStats?.total_flows || 0}
            icon={<NetworkCheck />}
            color="#00bcd4"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Findings"
            value={dashboardStats?.total_findings || 0}
            icon={<Warning />}
            color="#ff9800"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Critical"
            value={dashboardStats?.critical_findings || 0}
            icon={<Security />}
            color="#f44336"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Sensitive Artifacts"
            value={dashboardStats?.sensitive_artifacts || 0}
            icon={<Lock />}
            color="#9c27b0"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Plaintext Conns"
            value={dashboardStats?.plaintext_connections || 0}
            icon={<LockOpen />}
            color="#ff5722"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Encrypted Conns"
            value={dashboardStats?.encrypted_connections || 0}
            icon={<Lock />}
            color="#4caf50"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="DNS Queries (24h)"
            value={dashboardStats?.dns_queries_24h || 0}
            icon={<Dns />}
            color="#2196f3"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Hosts"
            value={(dashboardStats as any)?.total_hosts || 0}
            icon={<NetworkCheck />}
            color="#00e676"
          />
        </Grid>
      </Grid>

      {/* Charts and Tables */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 2, bgcolor: '#1e1e1e' }}>
            <Typography variant="h6" gutterBottom>
              Traffic Over Time
            </Typography>
            <TrafficChart data={dashboardStats?.traffic_over_time || []} />
          </Paper>
        </Grid>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2, bgcolor: '#1e1e1e' }}>
            <Typography variant="h6" gutterBottom>
              Top Talkers
            </Typography>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>IP Address</TableCell>
                  <TableCell align="right">Packets</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(dashboardStats?.top_talkers || []).slice(0, 5).map((talker) => (
                  <TableRow key={talker.ip}>
                    <TableCell>{talker.ip}</TableCell>
                    <TableCell align="right">{talker.packets.toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, bgcolor: '#1e1e1e' }}>
            <Typography variant="h6" gutterBottom>
              Top Destinations
            </Typography>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>IP Address</TableCell>
                  <TableCell align="right">Connections</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(dashboardStats?.top_destinations || []).slice(0, 5).map((dst) => (
                  <TableRow key={dst.ip}>
                    <TableCell>{dst.ip}</TableCell>
                    <TableCell align="right">{dst.connections.toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2, bgcolor: '#1e1e1e' }}>
            <Typography variant="h6" gutterBottom>
              Top Domains
            </Typography>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Domain</TableCell>
                  <TableCell align="right">Queries</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(dashboardStats?.top_domains || []).slice(0, 5).map((domain) => (
                  <TableRow key={domain.domain}>
                    <TableCell>{domain.domain}</TableCell>
                    <TableCell align="right">{domain.queries.toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}
