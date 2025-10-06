import { motion, AnimatePresence } from 'framer-motion'
import { useState, useEffect } from 'react'
import { rippleAnimation } from '@/utils/animations'

interface LiveBadgeProps {
  value?: number | string
  isLive?: boolean
  label?: string
}

export function LiveBadge({ value, isLive = true, label }: LiveBadgeProps) {
  const [prevValue, setPrevValue] = useState(value)
  const [showRipple, setShowRipple] = useState(false)

  useEffect(() => {
    if (value !== prevValue && value !== undefined) {
      setShowRipple(true)
      setTimeout(() => setShowRipple(false), 600)
      setPrevValue(value)
    }
  }, [value, prevValue])

  return (
    <div className="relative inline-flex items-center gap-2">
      {isLive && (
        <div className="relative">
          <motion.div
            className="w-2 h-2 bg-green-500 rounded-full"
            animate={{
              scale: [1, 1.2, 1],
              opacity: [1, 0.8, 1]
            }}
            transition={{
              duration: 1.5,
              repeat: Infinity,
              ease: 'easeInOut'
            }}
          />
          <AnimatePresence>
            {showRipple && (
              <motion.div
                className="absolute inset-0 bg-green-500 rounded-full"
                animate={rippleAnimation}
                exit={{ opacity: 0 }}
              />
            )}
          </AnimatePresence>
        </div>
      )}
      
      {label && <span className="text-gray-400 text-sm">{label}</span>}
      
      <AnimatePresence mode="wait">
        <motion.span
          key={value}
          initial={{ y: 10, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -10, opacity: 0 }}
          transition={{ duration: 0.2 }}
          className="text-white font-semibold tabular-nums"
        >
          {value}
        </motion.span>
      </AnimatePresence>
    </div>
  )
}
