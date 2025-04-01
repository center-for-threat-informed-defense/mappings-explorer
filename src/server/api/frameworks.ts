import { readFileSync } from 'fs'
import { join } from 'path'

export default defineEventHandler(() => {
  const filePath = join(process.cwd(), 'public/frameworks.json')
  const json = readFileSync(filePath, 'utf-8')
  return JSON.parse(json)
})