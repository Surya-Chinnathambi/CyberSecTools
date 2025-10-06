import { motion } from 'framer-motion'
import { ReactNode } from 'react'
import { floatAnimation, glowPulse, rotateAura, hoverScale, optimizedTransform } from '@/utils/animations'

interface GlowingCardProps {
  title: string
  children: ReactNode
  cta?: {
    text: string
    onClick: () => void
  }
  accentColor?: string
}

export function GlowingCard({ title, children, cta, accentColor = 'cyan' }: GlowingCardProps) {
  const colorMap: Record<string, string> = {
    cyan: 'from-cyan-500/50 via-blue-500/50 to-purple-500/50',
    purple: 'from-purple-500/50 via-pink-500/50 to-red-500/50',
    green: 'from-green-500/50 via-emerald-500/50 to-teal-500/50',
    red: 'from-red-500/50 via-orange-500/50 to-yellow-500/50'
  }

  return (
    <motion.div
      className="relative"
      animate={floatAnimation}
      whileHover={{ scale: 1.03, transition: { type: 'spring', stiffness: 400, damping: 10 } }}
      style={optimizedTransform}
    >
      <motion.div
        className={`absolute inset-0 bg-gradient-to-r ${colorMap[accentColor] || colorMap.cyan} blur-xl rounded-2xl`}
        animate={glowPulse}
        style={optimizedTransform}
      />
      
      <motion.div
        className={`absolute -inset-0.5 bg-gradient-to-r ${colorMap[accentColor] || colorMap.cyan} rounded-2xl opacity-75`}
        animate={rotateAura}
        style={optimizedTransform}
      />
      
      <div className="relative bg-gray-900/90 backdrop-blur-sm rounded-2xl p-6 border border-gray-800">
        <h3 className="text-xl font-bold text-white mb-4">{title}</h3>
        <div className="text-gray-300">{children}</div>
        
        {cta && (
          <motion.button
            onClick={cta.onClick}
            className={`mt-4 px-6 py-2 bg-gradient-to-r ${colorMap[accentColor] || colorMap.cyan} text-white rounded-lg font-semibold`}
            whileHover={hoverScale}
            whileTap={{ scale: 0.95 }}
            style={optimizedTransform}
          >
            {cta.text}
          </motion.button>
        )}
      </div>
    </motion.div>
  )
}
