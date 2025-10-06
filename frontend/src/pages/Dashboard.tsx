import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { GlowingCard } from '@/components/GlowingCard'
import { LiveBadge } from '@/components/LiveBadge'
import { LiveFeed } from '@/components/LiveFeed'
import { Skeleton } from '@/components/ProgressLoader'
import { dashboardAPI, authAPI } from '@/services/api'
import { staggerContainer, staggerItem } from '@/utils/animations'
import { useNavigate } from 'react-router-dom'

interface DashboardStats {
  total_scans: number
  vulnerabilities_found: number
  scans_remaining: number
  subscription_tier: string
}

interface ActivityItem {
  id: string
  message: string
  timestamp: Date
  type: 'info' | 'success' | 'warning' | 'error'
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [activity, setActivity] = useState<ActivityItem[]>([])
  const [user, setUser] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async () => {
    try {
      const [statsRes, activityRes, userRes] = await Promise.all([
        dashboardAPI.getStats(),
        dashboardAPI.getActivity(),
        authAPI.getMe()
      ])

      setStats(statsRes.data)
      setUser(userRes.data)
      
      const formattedActivity = activityRes.data.map((item: any) => ({
        id: item.id || Math.random().toString(),
        message: item.message,
        timestamp: new Date(item.timestamp),
        type: item.type || 'info'
      }))
      setActivity(formattedActivity)
    } catch (error) {
      console.error('Failed to load dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-48" />
          ))}
        </div>
      </div>
    )
  }

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="visible"
      className="space-y-8"
    >
      <motion.div variants={staggerItem}>
        <h1 className="text-4xl font-bold text-white mb-2">
          Welcome back, {user?.username || 'User'}!
        </h1>
        <div className="flex items-center gap-3">
          <LiveBadge 
            value={stats?.subscription_tier || 'Free'} 
            label="Plan:" 
            isLive={false}
          />
          <LiveBadge 
            value={stats?.scans_remaining || 0} 
            label="Scans Remaining:" 
            isLive={true}
          />
        </div>
      </motion.div>

      <motion.div
        variants={staggerContainer}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
      >
        <motion.div variants={staggerItem}>
          <GlowingCard
            title="Total Scans"
            accentColor="cyan"
            cta={{
              text: 'Start Scan',
              onClick: () => navigate('/port-scanner')
            }}
          >
            <LiveBadge value={stats?.total_scans || 0} isLive={true} />
          </GlowingCard>
        </motion.div>

        <motion.div variants={staggerItem}>
          <GlowingCard
            title="Vulnerabilities Found"
            accentColor="red"
            cta={{
              text: 'View Details',
              onClick: () => navigate('/reports')
            }}
          >
            <LiveBadge value={stats?.vulnerabilities_found || 0} isLive={true} />
          </GlowingCard>
        </motion.div>

        <motion.div variants={staggerItem}>
          <GlowingCard
            title="AI Chat"
            accentColor="purple"
            cta={{
              text: 'Open Chat',
              onClick: () => navigate('/ai-chat')
            }}
          >
            <p>Get AI-powered security analysis and recommendations</p>
          </GlowingCard>
        </motion.div>

        <motion.div variants={staggerItem}>
          <GlowingCard
            title="CVE Database"
            accentColor="green"
            cta={{
              text: 'Search CVEs',
              onClick: () => navigate('/cve-database')
            }}
          >
            <p>Search 200,000+ vulnerabilities from NVD</p>
          </GlowingCard>
        </motion.div>
      </motion.div>

      <motion.div variants={staggerItem}>
        <h2 className="text-2xl font-bold text-white mb-4">Activity Feed</h2>
        <LiveFeed items={activity} maxItems={50} />
      </motion.div>
    </motion.div>
  )
}
