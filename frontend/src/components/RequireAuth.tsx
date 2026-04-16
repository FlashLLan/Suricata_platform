import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/authStore'

export default function RequireAuth({ children }: { children: React.ReactNode }) {
  const { token, user, fetchMe, isLoading } = useAuthStore()
  const navigate = useNavigate()

  useEffect(() => {
    if (!token) {
      navigate('/login')
    } else if (!user) {
      fetchMe()
    }
  }, [token, user, navigate, fetchMe])

  if (!token) return null
  if (isLoading || !user) {
    return (
      <div className="min-h-screen bg-gray-950 flex items-center justify-center text-gray-400 text-sm">
        Loading…
      </div>
    )
  }

  return <>{children}</>
}
