import api from './client'
import type { SimulationResult } from '../types/lab'

export async function runSimulation(
  projectId: number,
  scenarioId: string,
  ruleTexts: string[],
  topology?: object,
): Promise<SimulationResult> {
  const { data } = await api.post<SimulationResult>('/simulate', {
    project_id: projectId,
    scenario_id: scenarioId,
    rule_texts: ruleTexts,
    topology,
  })
  return data
}
