import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { billingAPI } from '@/services/api'
import { showToast } from '@/components/ToastSystem'
import { GlowingCard } from '@/components/GlowingCard'
import { Skeleton } from '@/components/ProgressLoader'
import { CheckIcon } from '@heroicons/react/24/outline'
import { staggerContainer, staggerItem } from '@/utils/animations'

export default function Billing() {
  const [plans, setPlans] = useState<any[]>([])
  const [subscription, setSubscription] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    loadBillingData()
  }, [])

  const loadBillingData = async () => {
    try {
      const [plansRes, subRes] = await Promise.all([
        billingAPI.getPlans(),
        billingAPI.getSubscription()
      ])
      setPlans(plansRes.data.plans || [])
      setSubscription(subRes.data)
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Failed to load billing data')
    } finally {
      setIsLoading(false)
    }
  }

  const handleSubscribe = async (plan: string) => {
    try {
      const response = await billingAPI.createCheckout(plan)
      if (response.data.url) {
        window.location.href = response.data.url
      }
    } catch (error: any) {
      showToast.error(error.response?.data?.detail || 'Failed to create checkout')
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-64" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-96" />
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
        <h1 className="text-4xl font-bold text-white mb-2">Subscription Plans</h1>
        <p className="text-gray-400">Choose the plan that fits your security needs</p>
      </motion.div>

      {subscription && (
        <motion.div variants={staggerItem}>
          <div className="p-4 bg-blue-900/30 border border-blue-700 rounded-lg">
            <p className="text-blue-400">
              Current Plan: <span className="font-bold">{subscription.tier}</span>
              {subscription.scans_used !== undefined && (
                <span className="ml-4">
                  Scans Used: {subscription.scans_used} / {subscription.scan_limit || '∞'}
                </span>
              )}
            </p>
          </div>
        </motion.div>
      )}

      <motion.div
        variants={staggerContainer}
        className="grid grid-cols-1 md:grid-cols-3 gap-6"
      >
        {plans.map((plan: any, idx: number) => (
          <motion.div key={idx} variants={staggerItem}>
            <GlowingCard
              title={plan.name}
              accentColor={plan.name === 'Pro' ? 'purple' : plan.name === 'Enterprise' ? 'cyan' : 'green'}
              cta={{
                text: subscription?.tier === plan.name ? 'Current Plan' : `Subscribe - $${plan.price}/mo`,
                onClick: () => handleSubscribe(plan.id)
              }}
            >
              <div className="space-y-4">
                <p className="text-3xl font-bold text-white">${plan.price}<span className="text-lg text-gray-400">/mo</span></p>
                <ul className="space-y-2">
                  {plan.features.map((feature: string, fIdx: number) => (
                    <li key={fIdx} className="flex items-center gap-2 text-gray-300">
                      <CheckIcon className="w-5 h-5 text-green-500" />
                      {feature}
                    </li>
                  ))}
                </ul>
              </div>
            </GlowingCard>
          </motion.div>
        ))}
      </motion.div>
    </motion.div>
  )
}
