import { motion } from 'framer-motion'
import { useEffect, useState } from 'react'

interface ProgressLoaderProps {
  isLoading: boolean
}

export function ProgressLoader({ isLoading }: ProgressLoaderProps) {
  const [progress, setProgress] = useState(0)

  useEffect(() => {
    if (isLoading) {
      setProgress(0)
      const interval = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 90) return prev
          return prev + Math.random() * 15
        })
      }, 200)

      return () => clearInterval(interval)
    } else {
      setProgress(100)
      const timeout = setTimeout(() => setProgress(0), 300)
      return () => clearTimeout(timeout)
    }
  }, [isLoading])

  if (progress === 0) return null

  return (
    <motion.div
      className="fixed top-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 z-50 origin-left"
      initial={{ scaleX: 0 }}
      animate={{ scaleX: progress / 100 }}
      transition={{ duration: 0.2, ease: 'easeOut' }}
      style={{ transformOrigin: 'left' }}
    />
  )
}

export function Skeleton({ className = '' }: { className?: string }) {
  return (
    <motion.div
      className={`bg-gray-800 rounded ${className}`}
      animate={{
        opacity: [0.5, 0.8, 0.5]
      }}
      transition={{
        duration: 1.5,
        repeat: Infinity,
        ease: 'easeInOut'
      }}
    />
  )
}
