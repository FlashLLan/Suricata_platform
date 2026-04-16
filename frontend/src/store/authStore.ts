import { create } from 'zustand'
import { type User, getMe } from '../api/auth'

interface AuthState {
  user: User | null
  token: string | null
  isLoading: boolean
  setToken: (token: string) => void
  logout: () => void
  fetchMe: () => Promise<void>
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: localStorage.getItem('token'),
  isLoading: false,

  setToken: (token) => {
    localStorage.setItem('token', token)
    set({ token })
  },

  logout: () => {
    localStorage.removeItem('token')
    set({ user: null, token: null })
  },

  fetchMe: async () => {
    set({ isLoading: true })
    try {
      const user = await getMe()
      set({ user, isLoading: false })
    } catch {
      set({ user: null, token: null, isLoading: false })
      localStorage.removeItem('token')
    }
  },
}))
