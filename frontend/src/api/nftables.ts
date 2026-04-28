import api from './client'

export interface NftablesValidationResult {
  valid: boolean
  errors: string[]
  raw_output: string
  docker_available: boolean
}

export async function validateNftablesConfig(config: string): Promise<NftablesValidationResult> {
  const { data } = await api.post<NftablesValidationResult>('/nftables/validate', { config })
  return data
}
