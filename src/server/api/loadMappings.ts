// server/api/load-mapping.ts
import { readFile } from 'fs/promises'
import { join } from 'path'

export default defineEventHandler(async (event) => {
  const { path } = getQuery(event)
  if (!path) {
    throw createError({ statusCode: 400, message: 'Missing path param' })
  }

  const filePath = join(process.cwd(), 'public', path as string)
  const fileContent = await readFile(filePath, 'utf-8')

  return JSON.parse(fileContent)
})