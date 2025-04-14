'use client';

import React from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { Badge } from '@/components/ui/badge';

export function Hero() {
  return (
    <div className="relative min-h-screen bg-gradient-to-b from-background to-background/50 overflow-hidden">
      {/* Background decoration */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 rounded-full bg-primary/10 blur-3xl" />
        <div className="absolute top-1/4 -left-40 w-80 h-80 rounded-full bg-secondary/10 blur-3xl" />
        <div className="absolute bottom-20 right-20 w-60 h-60 rounded-full bg-accent/10 blur-3xl" />
      </div>

      {/* Hero content */}
      <div className="container relative z-10 mx-auto px-4 pt-32 pb-20 flex flex-col items-center text-center gap-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <Badge variant="secondary" className="mb-4 px-3 py-1 text-sm">
            Website Security Audit Tool
          </Badge>
        </motion.div>

        <motion.h1
          className="text-4xl md:text-6xl font-bold tracking-tight"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
        >
          <span className="text-primary">Secure</span> Your Website
          <br /> With Powerful Audit Scripts
        </motion.h1>

        <motion.p
          className="max-w-lg text-muted-foreground text-xl"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          Identify vulnerabilities, strengthen your defenses, and keep your
          website safe from threats with our advanced security audit tools.
        </motion.p>

        <motion.div
          className="flex flex-col sm:flex-row gap-4 mt-6"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
        >
          <Link
            href="/audit"
            className="inline-flex h-12 items-center justify-center rounded-md bg-primary px-8 text-lg font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
          >
            Start Security Audit
          </Link>
          <Link
            href="/learn"
            className="inline-flex h-12 items-center justify-center rounded-md border border-input bg-background px-8 text-lg font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
          >
            Learn More
          </Link>
        </motion.div>
      </div>

      {/* Floating animation for security icons */}
      <div className="absolute inset-0 z-0 opacity-20 pointer-events-none">
        <motion.div
          className="absolute top-20 left-[15%] text-4xl"
          animate={{ y: [0, -10, 0] }}
          transition={{ repeat: Infinity, duration: 3, ease: 'easeInOut' }}
        >
          🔒
        </motion.div>
        <motion.div
          className="absolute top-40 right-[20%] text-4xl"
          animate={{ y: [0, -15, 0] }}
          transition={{
            repeat: Infinity,
            duration: 4,
            ease: 'easeInOut',
            delay: 1,
          }}
        >
          🛡️
        </motion.div>
        <motion.div
          className="absolute bottom-32 left-[25%] text-4xl"
          animate={{ y: [0, -12, 0] }}
          transition={{
            repeat: Infinity,
            duration: 3.5,
            ease: 'easeInOut',
            delay: 0.5,
          }}
        >
          📊
        </motion.div>
        <motion.div
          className="absolute bottom-40 right-[30%] text-4xl"
          animate={{ y: [0, -8, 0] }}
          transition={{
            repeat: Infinity,
            duration: 2.5,
            ease: 'easeInOut',
            delay: 1.5,
          }}
        >
          🔍
        </motion.div>
      </div>
    </div>
  );
}
