import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'

export default function TargetForm() {
  const { id } = useParams()
  const navigate = useNavigate()
  const isEdit = !!id
  
  const [formData, setFormData] = useState({ name: '', url: '', notes: '' })
  
  // Load existing target for edit mode
  const { data: existingTarget } = useQuery({
    queryKey: ['target', id],
    queryFn: async () => {
      if (!isEdit) return null
      const res = await fetch(`/api/targets/${id}`)
      return res.json()
    },
    enabled: isEdit,
  })
  
  if (existingTarget && !formData.name) {
    setFormData({
      name: existingTarget.name,
      url: existingTarget.url,
      notes: existingTarget.notes || '',
    })
  }
  
  const mutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const url = isEdit ? `/api/targets/${id}` : '/api/targets'
      const method = isEdit ? 'PUT' : 'POST'
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!res.ok) throw new Error('Failed to save target')
      return res.json()
    },
    onSuccess: () => {
      navigate('/targets')
    },
  })
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    mutation.mutate(formData)
  }
  
  return (
    <div className="max-w-2xl">
      <h2 className="text-2xl font-bold mb-6">{isEdit ? 'Edit Target' : 'New Target'}</h2>
      
      <form onSubmit={handleSubmit} className="card space-y-4">
        <div>
          <label className="block text-sm text-gray-400 mb-1">Name</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            className="input-field"
            placeholder="e.g., Lab Environment"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm text-gray-400 mb-1">URL or IP</label>
          <input
            type="text"
            value={formData.url}
            onChange={(e) => setFormData({ ...formData, url: e.target.value })}
            className="input-field"
            placeholder="e.g., lab.local or 192.168.1.1"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm text-gray-400 mb-1">Notes</label>
          <textarea
            value={formData.notes}
            onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
            className="input-field"
            rows={3}
            placeholder="Optional notes about this target..."
          />
        </div>
        
        <div className="flex gap-3 pt-4">
          <button type="submit" className="btn-primary" disabled={mutation.isPending}>
            {mutation.isPending ? 'Saving...' : isEdit ? 'Update Target' : 'Create Target'}
          </button>
          <button
            type="button"
            onClick={() => navigate('/targets')}
            className="px-4 py-2 rounded-md border border-gray-600 hover:bg-gray-700"
          >
            Cancel
          </button>
        </div>
        
        {mutation.isError && (
          <div className="text-red-400 text-sm">
            Failed to save target. Please try again.
          </div>
        )}
      </form>
    </div>
  )
}
