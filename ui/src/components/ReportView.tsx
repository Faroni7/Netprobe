import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Download, ChevronRight, ChevronDown } from 'lucide-react'
import { useState } from 'react'

export default function ReportView() {
  const { id } = useParams()
  const [expandedPhases, setExpandedPhases] = useState<number[]>([])
  
  const { data: report, isLoading } = useQuery({
    queryKey: ['report', id],
    queryFn: async () => {
      const res = await fetch(`/api/reports/${id}`)
      if (!res.ok) throw new Error('Report not found')
      return res.json()
    },
  })
  
  if (isLoading) return <div className="text-gray-400">Loading report...</div>
  if (!report) return <div className="text-red-400">Report not found</div>
  
  const togglePhase = (idx: number) => {
    setExpandedPhases(prev => 
      prev.includes(idx) ? prev.filter(i => i !== idx) : [...prev, idx]
    )
  }
  
  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold">Report - Scan #{id}</h2>
        <div className="flex gap-2">
          <a href={`/api/reports/${id}/export/json`} download className="btn-primary flex items-center gap-2">
            <Download className="w-4 h-4" /> JSON
          </a>
          <a href={`/api/reports/${id}/export/markdown`} download className="px-4 py-2 rounded-md border border-gray-600 hover:bg-gray-700 flex items-center gap-2">
            <Download className="w-4 h-4" /> Markdown
          </a>
          <a href={`/api/reports/${id}/export/html`} download className="px-4 py-2 rounded-md border border-gray-600 hover:bg-gray-700 flex items-center gap-2">
            <Download className="w-4 h-4" /> HTML
          </a>
        </div>
      </div>
      
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-8">
        <SummaryCard label="Endpoints" value={report.summary.total_endpoints} />
        <SummaryCard label="API Routes" value={report.summary.api_routes} />
        <SummaryCard label="Auth" value={report.summary.authentication_mechanisms} />
        <SummaryCard label="Debug" value={report.summary.debug_interfaces} />
        <SummaryCard label="Suspicious" value={report.summary.suspicious_parameters} color="text-yellow-400" />
        <SummaryCard label="Vulns" value={report.summary.possible_vulns} color="text-red-400" />
        <SummaryCard label="Missing" value={report.summary.missing_controls} color="text-orange-400" />
      </div>
      
      {/* Target Info */}
      <div className="card mb-8">
        <h3 className="text-lg font-semibold mb-4">Target Information</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="text-gray-400 text-sm">Name:</span>
            <p className="font-medium">{report.target_name}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">URL:</span>
            <p className="font-medium text-blue-400">{report.target_url}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Status:</span>
            <p className={`font-medium status-${report.status}`}>{report.status}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Completed:</span>
            <p className="font-medium">{report.completed_at ? new Date(report.completed_at).toLocaleString() : 'N/A'}</p>
          </div>
        </div>
      </div>
      
      {/* Phases */}
      <div className="card mb-8">
        <h3 className="text-lg font-semibold mb-4">Reconnaissance Phases</h3>
        {report.phases.map((phase: any, idx: number) => (
          <div key={idx} className="border-b border-gray-700 last:border-0">
            <button
              onClick={() => togglePhase(idx)}
              className="w-full flex items-center justify-between py-3 hover:bg-gray-700 px-2 rounded transition-colors"
            >
              <div className="flex items-center gap-3">
                {expandedPhases.includes(idx) ? (
                  <ChevronDown className="w-5 h-5 text-gray-400" />
                ) : (
                  <ChevronRight className="w-5 h-5 text-gray-400" />
                )}
                <span className="font-medium">{phase.phase_name}</span>
                <span className={`status-${phase.status}`}>{phase.status}</span>
              </div>
              <span className="text-gray-400 text-sm">{phase.findings_count} findings</span>
            </button>
            {expandedPhases.includes(idx) && phase.data && (
              <div className="p-4 bg-gray-900 rounded mb-3 ml-8">
                <pre className="text-xs text-gray-300 overflow-auto max-h-64">
                  {JSON.stringify(phase.data, null, 2)}
                </pre>
              </div>
            )}
          </div>
        ))}
      </div>
      
      {/* Endpoints */}
      {report.endpoints && report.endpoints.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Discovered Endpoints ({report.endpoints.length})</h3>
          <div className="max-h-64 overflow-auto">
            <ul className="space-y-1">
              {report.endpoints.map((ep: string, idx: number) => (
                <li key={idx} className="font-mono text-sm text-gray-300 bg-gray-900 px-2 py-1 rounded">
                  {ep}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}

function SummaryCard({ label, value, color = 'text-white' }: { label: string, value: number, color?: string }) {
  return (
    <div className="card text-center">
      <h4 className="text-gray-400 text-xs uppercase mb-1">{label}</h4>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  )
}
