'use client';

import React from 'react';
import { motion } from 'framer-motion';
import {
  Search,
  Shield,
  AlertTriangle,
  FileCheck,
  BarChart,
  CheckCircle,
} from 'lucide-react';

type ProcessStepProps = {
  icon: React.ReactNode;
  title: string;
  description: string;
  index: number;
};

const ProcessStep = ({ icon, title, description, index }: ProcessStepProps) => {
  return (
    <motion.div
      className="relative flex flex-col md:flex-row items-center gap-4 md:gap-8"
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: index * 0.1 }}
      viewport={{ once: true, margin: '-100px' }}
    >
      {/* Step number and connector line */}
      <div className="flex flex-col items-center">
        <motion.div
          className="flex items-center justify-center w-14 h-14 rounded-full bg-primary/10 text-primary border-2 border-primary z-10"
          whileHover={{ scale: 1.05 }}
        >
          {icon}
        </motion.div>
        {index < 5 && (
          <div className="hidden md:block absolute top-7 left-7 h-full w-0.5 bg-border" />
        )}
      </div>

      {/* Step content */}
      <div className="flex-1 text-center md:text-left">
        <h3 className="text-xl font-bold mb-2">{title}</h3>
        <p className="text-muted-foreground">{description}</p>
      </div>
    </motion.div>
  );
};

export function Process() {
  const steps = [
    {
      icon: <Search className="h-6 w-6" />,
      title: 'Initial Website Scan',
      description:
        "We analyze your website's technical structure to identify potential security vulnerabilities and entry points.",
    },
    {
      icon: <AlertTriangle className="h-6 w-6" />,
      title: 'Vulnerability Detection',
      description:
        'Our security scripts identify and catalog all potential security issues, from SQL injections to XSS vulnerabilities.',
    },
    {
      icon: <Shield className="h-6 w-6" />,
      title: 'Threat Assessment',
      description:
        "Each vulnerability is evaluated and ranked based on its severity and potential impact on your website's security.",
    },
    {
      icon: <FileCheck className="h-6 w-6" />,
      title: 'Detailed Reporting',
      description:
        'You receive a comprehensive report highlighting all security issues with clear explanations and recommendations.',
    },
    {
      icon: <BarChart className="h-6 w-6" />,
      title: 'Solution Implementation',
      description:
        "Our team provides actionable steps to address identified vulnerabilities and enhance your website's security posture.",
    },
    {
      icon: <CheckCircle className="h-6 w-6" />,
      title: 'Ongoing Monitoring',
      description:
        'Continuous security monitoring to ensure your website remains protected from evolving threats and vulnerabilities.',
    },
  ];

  return (
    <section className="py-24 bg-muted/10">
      <div className="container mx-auto px-4">
        <div className="text-center mb-16">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            viewport={{ once: true }}
          >
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Our <span className="text-primary">Security Audit</span> Process
            </h2>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              We follow a systematic approach to identify, assess, and address
              security vulnerabilities on your website
            </p>
          </motion.div>
        </div>

        <div className="max-w-3xl mx-auto space-y-16 md:space-y-24">
          {steps.map((step, index) => (
            <ProcessStep
              key={index}
              icon={step.icon}
              title={step.title}
              description={step.description}
              index={index}
            />
          ))}
        </div>
      </div>
    </section>
  );
}
