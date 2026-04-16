import api from './client'

export interface ProjectSummary {
  id: number
  name: string
  description: string | null
  created_at: string
  updated_at: string
  last_opened_at: string
}

export interface Project extends ProjectSummary {
  user_id: number
  topology_json: string | null
  rules_json: string | null
  simulation_json: string | null
  export_json: string | null
}

export async function listProjects(): Promise<ProjectSummary[]> {
  const { data } = await api.get<ProjectSummary[]>('/projects')
  return data
}

export async function createProject(name: string, description?: string): Promise<Project> {
  const { data } = await api.post<Project>('/projects', { name, description })
  return data
}

export async function getProject(id: number): Promise<Project> {
  const { data } = await api.get<Project>(`/projects/${id}`)
  return data
}

export async function updateProject(id: number, patch: Partial<Omit<Project, 'id' | 'user_id' | 'created_at' | 'updated_at' | 'last_opened_at'>>): Promise<Project> {
  const { data } = await api.patch<Project>(`/projects/${id}`, patch)
  return data
}

export async function deleteProject(id: number): Promise<void> {
  await api.delete(`/projects/${id}`)
}
