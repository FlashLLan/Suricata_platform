import api from './client'
import type { SimulationResult } from '../types/lab'

export interface DockerStatus {
  state: 'docker_unavailable' | 'image_not_pulled' | 'ready'
  ready: boolean
  docker_running: boolean
  image_available: boolean
  error: string | null
  image: string
}

export async function checkStatus(): Promise<DockerStatus> {
  const { data } = await api.get<DockerStatus>('/simulate/status')
  return data
}

export async function runSimulation(
  projectId: number,
  scenarioId: string,
  ruleTexts: string[],
  topology?: object,
  mode: 'python' | 'suricata' = 'python',
  customCommands?: string,
): Promise<SimulationResult> {
  const { data } = await api.post<SimulationResult>('/simulate', {
    project_id: projectId,
    scenario_id: scenarioId,
    rule_texts: ruleTexts,
    topology,
    mode,
    custom_commands: customCommands || undefined,
  })
  return data
}
