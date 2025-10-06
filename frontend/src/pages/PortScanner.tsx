import { useState } from 'react'
import { motion } from 'framer-motion'
import { scanAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { GlowingCard } from '@/components/GlowingCard'
import { Skeleton } from '@/components/ProgressLoader'
import { scaleIn, staggerContainer, staggerItem } from '@/utils/animations'

export default function PortScanner() {
  const [host, setHost] = useState('')
  const [ports, setPorts] = useState('')
  const [scanType, setScanType] = useState('quick')
  const [results, setResults] = useState<any>(null)
  const [isScanning, setIsScanning] = useState(false)

  const handleScan = async () => {
    if (!host) {
      showToast.error('Please enter a host to scan')
      return
    }

    setIsScanning(true)
    setResults(null)

    try {
      const portArray = ports ? ports.split(',').map(p => parseInt(p.trim())) : undefined
      const response = await scanAPI.portScan(host, portArray, scanType)
      setResults(response.data)
      showToast.success('Scan completed successfully!')
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Scan failed')
    } finally {
      setIsScanning(false)
    }
  }

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="visible"
      className="space-y-8"
    >
      <motion.div variants={staggerItem}>
        <h1 className="text-4xl font-bold text-white mb-2">Port Scanner</h1>
        <p className="text-gray-400">Scan network ports to discover services and potential vulnerabilities</p>
      </motion.div>

      <motion.div variants={staggerItem}>
        <GlowingCard title="Scan Configuration" accentColor="cyan">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Target Host
              </label>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="e.g., scanme.nmap.org or 192.168.1.1"
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Ports (optional, comma-separated)
              </label>
              <input
                type="text"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                placeholder="e.g., 80,443,8080 or leave empty for common ports"
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Scan Type
              </label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 text-white"
              >
                <option value="quick">Quick Scan</option>
                <option value="full">Full Scan</option>
                <option value="stealth">Stealth Scan</option>
              </select>
            </div>

            <motion.button
              onClick={handleScan}
              disabled={isScanning}
              className="w-full py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-lg disabled:opacity-50"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {isScanning ? 'Scanning...' : 'Start Scan'}
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
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-gray-400 text-sm">Host</p>
                  <p className="text-white font-semibold">{results.host}</p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm">Open Ports</p>
                  <p className="text-white font-semibold">{results.open_ports?.length || 0}</p>
                </div>
              </div>

              {results.open_ports && results.open_ports.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-white font-semibold mb-2">Open Ports:</h4>
                  <div className="space-y-2">
                    {results.open_ports.map((port: any, idx: number) => (
                      <motion.div
                        key={idx}
                        initial={{ x: -20, opacity: 0 }}
                        animate={{ x: 0, opacity: 1 }}
                        transition={{ delay: idx * 0.05 }}
                        className="p-3 bg-gray-800 rounded-lg border border-gray-700"
                      >
                        <div className="flex justify-between items-center">
                          <span className="text-cyan-400 font-mono">Port {port.port}</span>
                          <span className="text-gray-400">{port.service}</span>
                        </div>
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
