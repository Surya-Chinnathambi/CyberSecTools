import { motion } from 'framer-motion'
import { ReactNode } from 'react'

interface AnimatedIconProps {
  icon: ReactNode
  onClick?: () => void
  hoverEffect?: 'pop' | 'rotate' | 'colorShift'
  className?: string
  ariaLabel?: string
}

export function AnimatedIcon({ 
  icon, 
  onClick, 
  hoverEffect = 'pop', 
  className = '',
  ariaLabel 
}: AnimatedIconProps) {
  const effects = {
    pop: {
      whileHover: { scale: 1.2 },
      whileTap: { scale: 0.9 }
    },
    rotate: {
      whileHover: { rotate: 15 },
      whileTap: { rotate: -15 }
    },
    colorShift: {
      whileHover: { filter: 'hue-rotate(90deg)' },
      whileTap: { scale: 0.95 }
    }
  }

  return (
    <motion.button
      onClick={onClick}
      className={`inline-flex items-center justify-center focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-lg ${className}`}
      {...effects[hoverEffect]}
      transition={{ type: 'spring', stiffness: 400, damping: 17 }}
      aria-label={ariaLabel}
      tabIndex={0}
      style={{ 
        willChange: 'transform',
        transform: 'translateZ(0)'
      }}
    >
      {icon}
    </motion.button>
  )
}
