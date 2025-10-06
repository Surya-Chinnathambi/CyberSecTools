import { useState } from 'react'
import { motion } from 'framer-motion'
import { scanAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { GlowingCard } from '@/components/GlowingCard'
import { Skeleton } from '@/components/ProgressLoader'
import { scaleIn, staggerContainer, staggerItem } from '@/utils/animations'

export default function WebScanner() {
  const [url, setUrl] = useState('')
  const [results, setResults] = useState<any>(null)
  const [isScanning, setIsScanning] = useState(false)

  const handleScan = async () => {
    if (!url) {
      showToast.error('Please enter a URL to scan')
      return
    }

    setIsScanning(true)
    setResults(null)

    try {
      const response = await scanAPI.webScan(url)
      setResults(response.data)
      showToast.success('Web scan completed successfully!')
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Scan failed')
    } finally {
      setIsScanning(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'text-red-500',
      high: 'text-orange-500',
      medium: 'text-yellow-500',
      low: 'text-blue-500',
      info: 'text-gray-500'
    }
    return colors[severity.toLowerCase()] || 'text-gray-500'
  }

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="visible"
      className="space-y-8"
    >
      <motion.div variants={staggerItem}>
        <h1 className="text-4xl font-bold text-white mb-2">Web Vulnerability Scanner</h1>
        <p className="text-gray-400">Scan websites for security vulnerabilities and misconfigurations</p>
      </motion.div>

      <motion.div variants={staggerItem}>
        <GlowingCard title="Web Scan Configuration" accentColor="purple">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target URL
              </label>
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-purple-500 text-white"
              />
            </div>

            <motion.button
              onClick={handleScan}
              disabled={isScanning}
              className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 text-white font-semibold rounded-lg disabled:opacity-50"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {isScanning ? 'Scanning...' : 'Start Web Scan'}
            </motion.button>
          </div>
        </GlowingCard>
      </motion.div>

      {isScanning && (
        <motion.div variants={scaleIn}>
          <Skeleton className="h-64" />
        </motion.div>
      )}

      {results && (
        <motion.div variants={scaleIn} initial="hidden" animate="visible">
          <GlowingCard title="Scan Results" accentColor="green">
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <p className="text-gray-400 text-sm">URL</p>
                  <p className="text-white font-semibold truncate">{results.url}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Status Code</p>
                  <p className="text-white font-semibold">{results.status_code}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Vulnerabilities</p>
                  <p className="text-white font-semibold">{results.vulnerabilities?.length || 0}</p>
                </div>
              </div>

              {results.vulnerabilities && results.vulnerabilities.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-white font-semibold mb-2">Vulnerabilities Found:</h4>
                  <div className="space-y-2">
                    {results.vulnerabilities.map((vuln: any, idx: number) => (
                      <motion.div
                        key={idx}
                        initial={{ x: -20, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        transition={{ delay: idx * 0.05 }}
                        className="p-4 bg-gray-800 rounded-lg border border-gray-700"
                      >
                        <div className="flex justify-between items-start mb-2">
                          <span className="text-white font-semibold">{vuln.type}</span>
                          <span className={`text-sm font-medium ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <p className="text-gray-400 text-sm">{vuln.description}</p>
                      </motion.div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </GlowingCard>
        </motion.div>
      )}
    </motion.div>
  )
}
