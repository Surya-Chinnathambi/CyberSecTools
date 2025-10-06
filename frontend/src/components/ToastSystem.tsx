import toast, { Toaster } from 'react-hot-toast'
import { motion } from 'framer-motion'
import Lottie from 'lottie-react'
import { CheckCircleIcon, XCircleIcon, InformationCircleIcon } from '@heroicons/react/24/outline'

const successLottie = {
  v: '5.5.7',
  fr: 60,
  ip: 0,
  op: 60,
  w: 100,
  h: 100,
  nm: 'Success',
  ddd: 0,
  assets: [],
  layers: [{
    ddd: 0,
    ind: 1,
    ty: 4,
    nm: 'Check',
    sr: 1,
    ks: {
      o: { a: 0, k: 100 },
      r: { a: 0, k: 0 },
      p: { a: 0, k: [50, 50, 0] },
      a: { a: 0, k: [0, 0, 0] },
      s: { a: 0, k: [100, 100, 100] }
    }
  }]
}

export function ToastSystem() {
  return (
    <Toaster
      position="bottom-right"
      toastOptions={{
        duration: 4000,
        style: {
          background: '#1F2937',
          color: '#F9FAFB',
          border: '1px solid #374151',
          borderRadius: '0.5rem'
        },
        success: {
          iconTheme: {
            primary: '#10B981',
            secondary: '#F9FAFB'
          }
        },
        error: {
          iconTheme: {
            primary: '#EF4444',
            secondary: '#F9FAFB'
          }
        }
      }}
    >
      {(t) => (
        <motion.div
          initial={{ opacity: 0, y: 50, scale: 0.3 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, scale: 0.5, transition: { duration: 0.2 } }}
          transition={{
            type: 'spring',
            stiffness: 500,
            damping: 40
          }}
        >
          {t.type === 'success' && (
            <div className="flex items-center gap-2">
              <CheckCircleIcon className="w-6 h-6 text-green-500" />
              <span>{t.message as string}</span>
            </div>
          )}
          {t.type === 'error' && (
            <div className="flex items-center gap-2">
              <XCircleIcon className="w-6 h-6 text-red-500" />
              <span>{t.message as string}</span>
            </div>
          )}
          {t.type === 'loading' && (
            <div className="flex items-center gap-2">
              <InformationCircleIcon className="w-6 h-6 text-blue-500" />
              <span>{t.message as string}</span>
            </div>
          )}
        </motion.div>
      )}
    </Toaster>
  )
}

export const showToast = {
  success: (message: string) => toast.success(message),
  error: (message: string) => toast.error(message),
  loading: (message: string) => toast.loading(message),
  dismiss: (toastId?: string) => toast.dismiss(toastId)
}
