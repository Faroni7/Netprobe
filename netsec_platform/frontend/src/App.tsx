import { Routes, Route, Navigate } from 'react-router-dom';
import { useEffect } from 'react';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Capture from './pages/Capture';
import Flows from './pages/Flows';
import Findings from './pages/Findings';
import Evidence from './pages/Evidence';
import Assets from './pages/Assets';
import DNS from './pages/DNS';
import Timeline from './pages/Timeline';
import NetworkGraph from './pages/NetworkGraph';
import Cases from './pages/Cases';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import Login from './pages/Login';
import { useAuthStore } from './store';
import { apiService } from './services/api';

function App() {
  const { isAuthenticated, login, logout } = useAuthStore();

  useEffect(() => {
    // Check if user is already logged in
    const token = apiService.getToken();
    if (token) {
      apiService.getCurrentUser()
        .then((user) => login(user))
        .catch(() => logout());
    }
  }, [login, logout]);

  return (
    <Routes>
      <Route path="/login" element={
        isAuthenticated ? <Navigate to="/dashboard" /> : <Login />
      } />
      
      <Route path="/" element={
        isAuthenticated ? <Layout /> : <Navigate to="/login" />
      }>
        <Route index element={<Navigate to="/dashboard" />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="capture" element={<Capture />} />
        <Route path="flows" element={<Flows />} />
        <Route path="findings" element={<Findings />} />
        <Route path="evidence" element={<Evidence />} />
        <Route path="assets" element={<Assets />} />
        <Route path="dns" element={<DNS />} />
        <Route path="timeline" element={<Timeline />} />
        <Route path="network-graph" element={<NetworkGraph />} />
        <Route path="cases" element={<Cases />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}

export default App;
