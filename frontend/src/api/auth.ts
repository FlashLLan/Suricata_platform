import api from './client'

export interface User {
  id: number
  email: string
  created_at: string
}

export async function register(email: string, password: string): Promise<User> {
  const { data } = await api.post<User>('/auth/register', { email, password })
  return data
}

export async function login(email: string, password: string): Promise<string> {
  const form = new URLSearchParams()
  form.append('username', email)
  form.append('password', password)
  const { data } = await api.post<{ access_token: string }>('/auth/login', form)
  return data.access_token
}

export async function getMe(): Promise<User> {
  const { data } = await api.get<User>('/auth/me')
  return data
}
