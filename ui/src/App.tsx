import { Routes, Route, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import TargetsList from './components/TargetsList'
import TargetForm from './components/TargetForm'
import ScansList from './components/ScansList'
import ScanView from './components/ScanView'
import ReportView from './components/ReportView'
import { Shield, Target, Activity, FileText } from 'lucide-react'

function App() {
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const res = await fetch('/api/health')
      return res.json()
    },
    refetchInterval: 10000,
  })

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-full w-64 bg-gray-800 border-r border-gray-700 p-4">
        <div className="flex items-center gap-2 mb-8">
          <Shield className="w-8 h-8 text-blue-500" />
          <h1 className="text-xl font-bold text-white">BlackBox Recon</h1>
        </div>
        
        <nav className="space-y-2">
          <Link to="/" className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-gray-700 transition-colors">
            <Activity className="w-5 h-5" />
            <span>Dashboard</span>
          </Link>
          <Link to="/targets" className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-gray-700 transition-colors">
            <Target className="w-5 h-5" />
            <span>Targets</span>
          </Link>
          <Link to="/scans" className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-gray-700 transition-colors">
            <Activity className="w-5 h-5" />
            <span>Scans</span>
          </Link>
          <Link to="/reports" className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-gray-700 transition-colors">
            <FileText className="w-5 h-5" />
            <span>Reports</span>
          </Link>
        </nav>
        
        <div className="absolute bottom-4 left-4 text-xs text-gray-500">
          {health?.status === 'healthy' ? '● Backend Connected' : '○ Backend Disconnected'}
        </div>
      </aside>
      
      {/* Main Content */}
      <main className="ml-64 p-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/targets" element={<TargetsList />} />
          <Route path="/targets/new" element={<TargetForm />} />
          <Route path="/targets/:id/edit" element={<TargetForm />} />
          <Route path="/scans" element={<ScansList />} />
          <Route path="/scans/:id" element={<ScanView />} />
          <Route path="/reports/:id" element={<ReportView />} />
        </Routes>
      </main>
    </div>
  )
}

function Dashboard() {
  const { data: targets } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch('/api/targets')
      return res.json()
    },
  })
  
  const { data: scans } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch('/api/scans')
      return res.json()
    },
  })
  
  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Dashboard</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Total Targets</h3>
          <p className="text-3xl font-bold">{targets?.length || 0}</p>
        </div>
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Total Scans</h3>
          <p className="text-3xl font-bold">{scans?.length || 0}</p>
        </div>
        <div className="card">
          <h3 className="text-gray-400 text-sm mb-2">Running Scans</h3>
          <p className="text-3xl font-bold text-blue-400">
            {scans?.filter((s: any) => s.status === 'running').length || 0}
          </p>
        </div>
      </div>
      
      <div className="card">
        <h3 className="text-lg font-semibold mb-4">Recent Scans</h3>
        {scans && scans.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400 text-sm">
                <th className="pb-3">ID</th>
                <th className="pb-3">Target</th>
                <th className="pb-3">Status</th>
                <th className="pb-3">Progress</th>
              </tr>
            </thead>
            <tbody>
              {scans.slice(0, 5).map((scan: any) => (
                <tr key={scan.id} className="border-t border-gray-700">
                  <td className="py-3">#{scan.id}</td>
                  <td className="py-3">Target #{scan.target_id}</td>
                  <td className={`py-3 status-${scan.status}`}>{scan.status}</td>
                  <td className="py-3">
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div 
                        className="bg-blue-500 h-2 rounded-full" 
                        style={{ width: `${scan.progress}%` }}
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-gray-500">No scans yet. Create a target and start a scan!</p>
        )}
      </div>
    </div>
  )
}

export default App
