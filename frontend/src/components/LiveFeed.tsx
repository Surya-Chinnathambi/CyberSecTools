import { motion, AnimatePresence } from 'framer-motion'
import { useState, useEffect, useRef } from 'react'
import { ArrowDownIcon } from '@heroicons/react/24/outline'

interface FeedItem {
  id: string
  message: string
  timestamp: Date
  type?: 'info' | 'success' | 'warning' | 'error'
}

interface LiveFeedProps {
  items: FeedItem[]
  maxItems?: number
}

export function LiveFeed({ items, maxItems = 50 }: LiveFeedProps) {
  const [autoScroll, setAutoScroll] = useState(true)
  const [showScrollButton, setShowScrollButton] = useState(false)
  const feedRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight
    }
  }, [items, autoScroll])

  const handleScroll = () => {
    if (feedRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = feedRef.current
      const isAtBottom = scrollHeight - scrollTop - clientHeight < 50
      setAutoScroll(isAtBottom)
      setShowScrollButton(!isAtBottom)
    }
  }

  const scrollToBottom = () => {
    if (feedRef.current) {
      feedRef.current.scrollTo({ top: feedRef.current.scrollHeight, behavior: 'smooth' })
      setAutoScroll(true)
    }
  }

  const typeColors = {
    info: 'text-blue-400',
    success: 'text-green-400',
    warning: 'text-yellow-400',
    error: 'text-red-400'
  }

  const displayItems = items.slice(-maxItems)

  return (
    <div className="relative h-96 bg-gray-900/50 rounded-lg border border-gray-800">
      <div
        ref={feedRef}
        onScroll={handleScroll}
        className="h-full overflow-y-auto p-4 space-y-2 scrollbar-thin scrollbar-thumb-gray-700 scrollbar-track-gray-900"
      >
        <AnimatePresence initial={false}>
          {displayItems.map((item) => (
            <motion.div
              key={item.id}
              initial={{ y: 20, opacity: 0, height: 0 }}
              animate={{ y: 0, opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.2 }}
              className={`font-mono text-sm ${typeColors[item.type || 'info']}`}
            >
              <span className="text-gray-500">{item.timestamp.toLocaleTimeString()}</span>
              {' '}{item.message}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      <AnimatePresence>
        {showScrollButton && (
          <motion.button
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 10 }}
            onClick={scrollToBottom}
            className="absolute bottom-4 right-4 p-2 bg-blue-600 hover:bg-blue-700 rounded-full shadow-lg"
          >
            <motion.div
              animate={{
                y: [0, 3, 0]
              }}
              transition={{
                duration: 1,
                repeat: Infinity
              }}
            >
              <ArrowDownIcon className="w-5 h-5 text-white" />
            </motion.div>
          </motion.button>
        )}
      </AnimatePresence>
    </div>
  )
}
