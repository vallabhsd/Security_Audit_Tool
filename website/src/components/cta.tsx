'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import { ArrowRight } from 'lucide-react';

export function CtaSection() {
  const [email, setEmail] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);

    // Simulate form submission
    setTimeout(() => {
      toast.success("Thanks for subscribing! We'll be in touch soon.", {
        position: 'top-center',
      });
      setEmail('');
      setIsSubmitting(false);
    }, 1500);
  };

  return (
    <section className="py-24 relative overflow-hidden">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-background to-secondary/5 -z-10" />

      {/* Animated background circles */}
      <motion.div
        className="absolute top-20 -right-40 w-96 h-96 rounded-full bg-primary/5 blur-3xl"
        animate={{
          scale: [1, 1.2, 1],
          opacity: [0.3, 0.2, 0.3],
        }}
        transition={{
          duration: 15,
          repeat: Infinity,
          repeatType: 'reverse',
        }}
      />

      <motion.div
        className="absolute -bottom-40 -left-40 w-96 h-96 rounded-full bg-secondary/5 blur-3xl"
        animate={{
          scale: [1, 1.1, 1],
          opacity: [0.2, 0.3, 0.2],
        }}
        transition={{
          duration: 12,
          repeat: Infinity,
          repeatType: 'reverse',
        }}
      />

      <div className="container mx-auto px-4">
        <div className="max-w-4xl mx-auto">
          <motion.div
            className="bg-card border border-border rounded-xl shadow-lg p-8 md:p-12"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            viewport={{ once: true, margin: '-100px' }}
          >
            <div className="text-center mb-8">
              <motion.h2
                className="text-3xl md:text-4xl font-bold mb-4"
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.1 }}
                viewport={{ once: true }}
              >
                Ready to <span className="text-primary">Secure</span> Your
                Website?
              </motion.h2>

              <motion.p
                className="text-xl text-muted-foreground max-w-2xl mx-auto"
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.2 }}
                viewport={{ once: true }}
              >
                Join our newsletter to receive security tips and updates about
                our audit tools.
              </motion.p>
            </div>

            <motion.form
              className="max-w-md mx-auto"
              onSubmit={handleSubmit}
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
              viewport={{ once: true }}
            >
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1">
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="Enter your email"
                    required
                    className="flex h-12 w-full rounded-md border border-input bg-background px-3 py-2 text-base ring-offset-background 
                      placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring 
                      focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                  />
                </div>
                <motion.button
                  type="submit"
                  disabled={isSubmitting}
                  className="inline-flex h-12 items-center justify-center rounded-md bg-primary px-6 text-base font-medium 
                    text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none 
                    focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
                  whileHover={{ scale: 1.03 }}
                  whileTap={{ scale: 0.98 }}
                >
                  {isSubmitting ? (
                    <span className="animate-spin mr-2">⏳</span>
                  ) : (
                    <ArrowRight className="mr-2 h-4 w-4" />
                  )}
                  Subscribe
                </motion.button>
              </div>
              <p className="text-xs text-muted-foreground mt-3 text-center">
                We respect your privacy. Unsubscribe at any time.
              </p>
            </motion.form>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
