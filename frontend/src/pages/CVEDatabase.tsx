import { useState } from 'react'
import { motion } from 'framer-motion'
import { cveAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { GlowingCard } from '@/components/GlowingCard'
import { Skeleton } from '@/components/ProgressLoader'
import { MagnifyingGlassIcon } from '@heroicons/react/24/outline'
import { staggerContainer, staggerItem, scaleIn } from '@/utils/animations'

export default function CVEDatabase() {
  const [keyword, setKeyword] = useState('')
  const [results, setResults] = useState<any[]>([])
  const [isSearching, setIsSearching] = useState(false)

  const handleSearch = async () => {
    if (!keyword.trim()) {
      showToast.error('Please enter a search keyword')
      return
    }

    setIsSearching(true)
    try {
      const response = await cveAPI.search(keyword)
      setResults(response.data.vulnerabilities || [])
      showToast.success(`Found ${response.data.vulnerabilities?.length || 0} CVEs`)
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Search failed')
    } finally {
      setIsSearching(false)
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
        <h1 className="text-4xl font-bold text-white mb-2">CVE Database</h1>
        <p className="text-gray-400">Search 200,000+ vulnerabilities from NIST NVD</p>
      </motion.div>

      <motion.div variants={staggerItem}>
        <GlowingCard title="Search CVEs" accentColor="green">
          <div className="flex gap-2">
            <input
              type="text"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Search by CVE ID, product, vendor..."
              className="flex-1 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg focus:ring-2 focus:ring-green-500 text-white"
            />
            <motion.button
              onClick={handleSearch}
              disabled={isSearching}
              className="px-6 py-2 bg-gradient-to-r from-green-600 to-emerald-600 text-white font-semibold rounded-lg disabled:opacity-50 flex items-center gap-2"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <MagnifyingGlassIcon className="w-5 h-5" />
              Search
            </motion.button>
          </div>
        </GlowingCard>
      </motion.div>

      {isSearching && (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-32" />
          ))}
        </div>
      )}

      {!isSearching && results.length > 0 && (
        <motion.div variants={staggerContainer} className="space-y-4">
          {results.map((cve: any, idx: number) => (
            <motion.div
              key={idx}
              variants={scaleIn}
              initial="hidden"
              animate="visible"
              transition={{ delay: idx * 0.05 }}
            >
              <div className="p-6 bg-gray-900/50 rounded-lg border border-gray-800 hover:border-green-500 transition-colors">
                <div className="flex justify-between items-start mb-3">
                  <h3 className="text-xl font-bold text-green-400">{cve.id}</h3>
                  <span className="px-3 py-1 bg-red-900/30 text-red-400 rounded-full text-sm font-medium">
                    Score: {cve.score || 'N/A'}
                  </span>
                </div>
                <p className="text-gray-300 mb-2">{cve.description}</p>
                <div className="flex gap-4 text-sm text-gray-500">
                  <span>Published: {cve.published || 'N/A'}</span>
                  {cve.severity && <span>Severity: {cve.severity}</span>}
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}
    </motion.div>
  )
}
