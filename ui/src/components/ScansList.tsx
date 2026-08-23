import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Play, Square, FileText } from 'lucide-react'

export default function ScansList() {
  const queryClient = useQueryClient()
  
  const { data: scans, isLoading, refetch } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await fetch('/api/scans')
      return res.json()
    },
    refetchInterval: 3000,
  })
  
  const startMutation = useMutation({
    mutationFn: async (id: number) => {
      await fetch(`/api/scans/${id}/start`, { method: 'POST' })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })
  
  const stopMutation = useMutation({
    mutationFn: async (id: number) => {
      await fetch(`/api/scans/${id}/stop`, { method: 'POST' })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })
  
  if (isLoading) return <div className="text-gray-400">Loading...</div>
  
  return (
    <div>
      <h2 className="text-2xl font-bold mb-6">Scans</h2>
      
      <div className="card">
        {scans && scans.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr className="text-left text-gray-400 text-sm">
                <th className="pb-3">ID</th>
                <th className="pb-3">Target</th>
                <th className="pb-3">Status</th>
                <th className="pb-3">Phase</th>
                <th className="pb-3">Progress</th>
                <th className="pb-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan: any) => (
                <tr key={scan.id} className="border-t border-gray-700">
                  <td className="py-3">#{scan.id}</td>
                  <td className="py-3">Target #{scan.target_id}</td>
                  <td className={`py-3 status-${scan.status}`}>{scan.status}</td>
                  <td className="py-3 text-gray-400">{scan.current_phase || '-'}</td>
                  <td className="py-3 w-48">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-gray-700 rounded-full h-2">
                        <div 
                          className="bg-blue-500 h-2 rounded-full transition-all" 
                          style={{ width: `${scan.progress}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-400">{Math.round(scan.progress)}%</span>
                    </div>
                  </td>
                  <td className="py-3">
                    <div className="flex gap-2">
                      {scan.status === 'pending' && (
                        <button
                          onClick={() => startMutation.mutate(scan.id)}
                          className="p-1 hover:bg-green-900 rounded text-green-400"
                          title="Start Scan"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                      )}
                      {scan.status === 'running' && (
                        <button
                          onClick={() => stopMutation.mutate(scan.id)}
                          className="p-1 hover:bg-red-900 rounded text-red-400"
                          title="Stop Scan"
                        >
                          <Square className="w-4 h-4" />
                        </button>
                      )}
                      {scan.status === 'completed' && (
                        <Link
                          to={`/reports/${scan.id}`}
                          className="p-1 hover:bg-blue-900 rounded text-blue-400"
                          title="View Report"
                        >
                          <FileText className="w-4 h-4" />
                        </Link>
                      )}
                      <Link
                        to={`/scans/${scan.id}`}
                        className="p-1 hover:bg-gray-700 rounded"
                        title="View Details"
                      >
                        <FileText className="w-4 h-4" />
                      </Link>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="text-center py-8 text-gray-500">
            No scans yet. Create a target and start a scan!
          </div>
        )}
      </div>
    </div>
  )
}
