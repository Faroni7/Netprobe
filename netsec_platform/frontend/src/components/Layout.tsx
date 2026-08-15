import { useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Avatar,
  Menu,
  MenuItem,
  Divider,
  Chip,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Capture as CaptureIcon,
  FlowChart as FlowsIcon,
  Warning as FindingsIcon,
  Evidence as EvidenceIcon,
  Computer as AssetsIcon,
  Dns as DNSIcon,
  Timeline as TimelineIcon,
  Graph as NetworkIcon,
  Folder as CasesIcon,
  Assessment as ReportsIcon,
  Settings as SettingsIcon,
  ExitToApp,
  AccountCircle,
  Emergency,
} from '@mui/icons-material';
import { useUIStore, useAuthStore, useCaptureStore } from '../store';
import { apiService } from '../services/api';
import EmergencyStopDialog from './EmergencyStopDialog';

const DRAWER_WIDTH = 240;

const menuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/dashboard' },
  { text: 'Capture', icon: <CaptureIcon />, path: '/capture' },
  { text: 'Flows', icon: <FlowsIcon />, path: '/flows' },
  { text: 'Findings', icon: <FindingsIcon />, path: '/findings' },
  { text: 'Evidence', icon: <EvidenceIcon />, path: '/evidence' },
  { text: 'Assets', icon: <AssetsIcon />, path: '/assets' },
  { text: 'DNS', icon: <DNSIcon />, path: '/dns' },
  { text: 'Timeline', icon: <TimelineIcon />, path: '/timeline' },
  { text: 'Network Graph', icon: <NetworkIcon />, path: '/network-graph' },
  { text: 'Cases', icon: <CasesIcon />, path: '/cases' },
  { text: 'Reports', icon: <ReportsIcon />, path: '/reports' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
];

export default function Layout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { sidebarOpen, toggleSidebar, setActivePage } = useUIStore();
  const { user, logout } = useAuthStore();
  const { essStatus } = useCaptureStore();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [essDialogOpen, setEssDialogOpen] = useState(false);

  const handleLogout = async () => {
    try {
      await apiService.logout();
      logout();
      navigate('/login');
    } catch (error) {
      console.error('Logout failed:', error);
      logout();
      navigate('/login');
    }
  };

  const handleESSClick = () => {
    setEssDialogOpen(true);
  };

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          zIndex: (theme) => theme.zIndex.drawer + 1,
          bgcolor: '#1e1e1e',
          borderBottom: '1px solid #333',
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            edge="start"
            onClick={toggleSidebar}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" noWrap sx={{ flexGrow: 1 }}>
            NetSec Platform
          </Typography>
          
          {/* ESS Status Indicator */}
          {essStatus && (
            <Chip
              label={`ESS: ${essStatus.state}`}
              color={essStatus.state === 'READY' ? 'success' : 'error'}
              sx={{ mr: 2 }}
            />
          )}
          
          {/* Emergency Stop Button */}
          <IconButton
            color="error"
            onClick={handleESSClick}
            sx={{ mr: 2 }}
            title="Emergency Security Stop"
          >
            <Emergency />
          </IconButton>
          
          {/* User Menu */}
          <IconButton onClick={(e) => setAnchorEl(e.currentTarget)} color="inherit">
            <Avatar sx={{ width: 32, height: 32, bgcolor: '#00bcd4' }}>
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </Avatar>
          </IconButton>
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={() => setAnchorEl(null)}
          >
            <MenuItem disabled>
              <AccountCircle sx={{ mr: 1 }} />
              {user?.username || 'User'}
            </MenuItem>
            <Divider />
            <MenuItem onClick={handleLogout}>
              <ExitToApp sx={{ mr: 1 }} />
              Logout
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>

      <Drawer
        variant="persistent"
        open={sidebarOpen}
        sx={{
          width: sidebarOpen ? DRAWER_WIDTH : 0,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: DRAWER_WIDTH,
            boxSizing: 'border-box',
            bgcolor: '#1e1e1e',
            borderRight: '1px solid #333',
          },
        }}
      >
        <Toolbar />
        <List>
          {menuItems.map((item) => (
            <ListItem key={item.text} disablePadding>
              <ListItemButton
                selected={location.pathname === item.path}
                onClick={() => {
                  setActivePage(item.text.toLowerCase());
                  navigate(item.path);
                }}
                sx={{
                  '&.Mui-selected': {
                    bgcolor: 'rgba(0, 188, 212, 0.1)',
                    borderRight: '3px solid #00bcd4',
                  },
                }}
              >
                <ListItemIcon sx={{ color: location.pathname === item.path ? '#00bcd4' : 'inherit' }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText primary={item.text} />
              </ListItemButton>
            </ListItem>
          ))}
        </List>
      </Drawer>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          ml: sidebarOpen ? `${DRAWER_WIDTH}px` : 0,
          mt: '64px',
          bgcolor: '#121212',
          minHeight: 'calc(100vh - 64px)',
        }}
      >
        <Outlet />
      </Box>

      <EmergencyStopDialog
        open={essDialogOpen}
        onClose={() => setEssDialogOpen(false)}
      />
    </Box>
  );
}
