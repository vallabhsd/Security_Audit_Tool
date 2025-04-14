'use client';

import React from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Terminal,
  AlertTriangle,
  RefreshCw,
  Lock,
  Code,
} from 'lucide-react';

type FeatureProps = {
  icon: React.ReactNode;
  title: string;
  description: string;
  index: number;
};

const FeatureCard = ({ icon, title, description, index }: FeatureProps) => {
  return (
    <motion.div
      className="group relative bg-card text-card-foreground p-6 rounded-lg shadow-sm border border-border 
        hover:shadow-md hover:border-primary/20 transition-all duration-300"
      initial={{ opacity: 0, y: 30 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: index * 0.1 }}
      viewport={{ once: true, margin: '-100px' }}
      whileHover={{ y: -5 }}
    >
      <div
        className="absolute -top-3 -left-3 rounded-full bg-primary/10 p-3 group-hover:bg-primary/90 
        transition-colors duration-300"
      >
        <div className="text-primary group-hover:text-primary-foreground transition-colors duration-300">
          {icon}
        </div>
      </div>
      <div className="pt-8">
        <h3 className="text-xl font-bold mb-2">{title}</h3>
        <p className="text-muted-foreground">{description}</p>
      </div>
    </motion.div>
  );
};

export function Features() {
  const features = [
    {
      icon: <Shield className="w-6 h-6" />,
      title: 'Vulnerability Detection',
      description:
        'Identify security weaknesses in your website before attackers can exploit them.',
    },
    {
      icon: <Terminal className="w-6 h-6" />,
      title: 'Advanced Scripting',
      description:
        'Custom audit scripts designed to thoroughly test every aspect of your website.',
    },
    {
      icon: <AlertTriangle className="w-6 h-6" />,
      title: 'Real-time Alerts',
      description:
        'Get immediate notifications when potential security threats are detected.',
    },
    {
      icon: <RefreshCw className="w-6 h-6" />,
      title: 'Continuous Monitoring',
      description:
        'Ongoing security checks that keep your website protected around the clock.',
    },
    {
      icon: <Lock className="w-6 h-6" />,
      title: 'Compliance Checks',
      description:
        'Ensure your website meets industry security standards and regulations.',
    },
    {
      icon: <Code className="w-6 h-6" />,
      title: 'Code Analysis',
      description:
        'Deep inspection of your website code to find hidden security flaws.',
    },
  ];

  return (
    <section className="py-24 bg-muted/30">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <motion.h2
            className="text-3xl md:text-4xl font-bold"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            viewport={{ once: true }}
          >
            Powerful Security <span className="text-primary">Features</span>
          </motion.h2>
          <motion.p
            className="mt-4 text-xl text-muted-foreground max-w-2xl mx-auto"
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            viewport={{ once: true }}
          >
            Our comprehensive suite of security tools helps protect your website
            from all types of cyber threats
          </motion.p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <FeatureCard
              key={index}
              icon={feature.icon}
              title={feature.title}
              description={feature.description}
              index={index}
            />
          ))}
        </div>
      </div>
    </section>
  );
}
