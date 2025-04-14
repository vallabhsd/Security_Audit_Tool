'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  ChevronDown,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Shield,
} from 'lucide-react';
import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

// Define types for security findings
type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: FindingSeverity;
  remediation: string;
}

interface CategoryScore {
  category: string;
  score: number;
  findings: Finding[];
  icon: React.ReactNode;
}

// Mockup data - this would be replaced with real API data
const mockScores: CategoryScore[] = [
  {
    category: 'SSL Configuration',
    score: 85,
    icon: <Shield className="h-5 w-5" />,
    findings: [
      {
        id: 'ssl-1',
        title: 'TLS 1.0/1.1 Enabled',
        description:
          'Your server supports outdated TLS protocols (1.0/1.1) which are considered insecure.',
        category: 'SSL Configuration',
        severity: 'medium',
        remediation:
          'Disable TLS 1.0 and 1.1 protocols on your server, and only allow TLS 1.2 and above.',
      },
      {
        id: 'ssl-2',
        title: 'Strong SSL Cipher Suite',
        description: 'Your server uses strong and modern cipher suites.',
        category: 'SSL Configuration',
        severity: 'info',
        remediation:
          'No action needed. Continue to maintain updated cipher suites.',
      },
    ],
  },
  {
    category: 'HTTP Headers',
    score: 65,
    icon: <AlertTriangle className="h-5 w-5" />,
    findings: [
      {
        id: 'header-1',
        title: 'Missing Security Headers',
        description:
          'Content-Security-Policy header is not set which may expose your site to XSS attacks.',
        category: 'HTTP Headers',
        severity: 'high',
        remediation:
          'Implement Content-Security-Policy headers with appropriate directives.',
      },
      {
        id: 'header-2',
        title: 'X-Frame-Options Header Missing',
        description:
          'X-Frame-Options header is not set which may allow clickjacking attacks.',
        category: 'HTTP Headers',
        severity: 'medium',
        remediation:
          'Add X-Frame-Options header with "SAMEORIGIN" or "DENY" value.',
      },
    ],
  },
  {
    category: 'Domain Security',
    score: 90,
    icon: <CheckCircle2 className="h-5 w-5" />,
    findings: [
      {
        id: 'domain-1',
        title: 'DNSSEC Enabled',
        description:
          'DNSSEC is properly enabled for your domain, protecting from DNS spoofing attacks.',
        category: 'Domain Security',
        severity: 'info',
        remediation: 'No action needed. Continue to maintain DNSSEC.',
      },
    ],
  },
  {
    category: 'Vulnerabilities',
    score: 40,
    icon: <XCircle className="h-5 w-5" />,
    findings: [
      {
        id: 'vuln-1',
        title: 'Outdated WordPress Version',
        description:
          'Your WordPress installation (version 5.7.2) is outdated and contains known security vulnerabilities.',
        category: 'Vulnerabilities',
        severity: 'critical',
        remediation: 'Update WordPress to the latest version immediately.',
      },
      {
        id: 'vuln-2',
        title: 'Vulnerable Plugin Detected',
        description:
          'The Contact Form 7 plugin (version 5.4.1) has a known XSS vulnerability.',
        category: 'Vulnerabilities',
        severity: 'high',
        remediation: 'Update the Contact Form 7 plugin to the latest version.',
      },
    ],
  },
];

// Calculate overall score based on category scores
const calculateOverallScore = (scores: CategoryScore[]): number => {
  if (scores.length === 0) return 0;
  const total = scores.reduce((sum, category) => sum + category.score, 0);
  return Math.round(total / scores.length);
};

// Component for expandable security finding
function FindingDetails({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  // Map severity to badge color
  const getSeverityBadge = (severity: FindingSeverity) => {
    switch (severity) {
      case 'critical':
        return <Badge variant="destructive">Critical</Badge>;
      case 'high':
        return <Badge variant="destructive">High</Badge>;
      case 'medium':
        return <Badge variant="secondary">Medium</Badge>;
      case 'low':
        return <Badge variant="secondary">Low</Badge>;
      case 'info':
        return <Badge variant="success">Info</Badge>;
      default:
        return <Badge>Unknown</Badge>;
    }
  };

  return (
    <div className="border border-border rounded-md mb-2 overflow-hidden">
      <div
        className="p-3 flex justify-between items-center cursor-pointer bg-card/50 hover:bg-card/80 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-2">
          {getSeverityBadge(finding.severity)}
          <h4 className="font-medium">{finding.title}</h4>
        </div>
        <ChevronDown
          className={`h-5 w-5 transition-transform ${
            expanded ? 'rotate-180' : ''
          }`}
        />
      </div>

      {expanded && (
        <div className="p-4 bg-background border-t border-border">
          <h5 className="font-semibold mb-2">Description</h5>
          <p className="text-muted-foreground mb-4">{finding.description}</p>

          <h5 className="font-semibold mb-2">Remediation</h5>
          <p className="text-muted-foreground">{finding.remediation}</p>
        </div>
      )}
    </div>
  );
}

// Category Card Component
function CategoryCard({ data }: { data: CategoryScore }) {
  const [expanded, setExpanded] = useState(false);

  // Get score color
  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-500';
    if (score >= 60) return 'text-yellow-500';
    return 'text-red-500';
  };

  return (
    <motion.div
      className="bg-card border border-border rounded-lg overflow-hidden"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <div className="p-4 flex justify-between items-center">
        <div className="flex items-center gap-3">
          <div
            className={`p-2 rounded-full ${
              data.score >= 80
                ? 'bg-green-500/10'
                : data.score >= 60
                ? 'bg-yellow-500/10'
                : 'bg-red-500/10'
            }`}
          >
            {data.icon}
          </div>
          <h3 className="text-lg font-semibold">{data.category}</h3>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-xl font-bold">
            <span className={getScoreColor(data.score)}>{data.score}</span>
            <span className="text-sm text-muted-foreground">/100</span>
          </div>

          <Button
            variant="ghost"
            size="icon"
            onClick={() => setExpanded(!expanded)}
          >
            <ChevronDown
              className={`transition-transform ${expanded ? 'rotate-180' : ''}`}
            />
          </Button>
        </div>
      </div>

      {expanded && (
        <div className="p-4 border-t border-border bg-background/50">
          <h4 className="font-medium mb-3">
            Findings ({data.findings.length})
          </h4>
          {data.findings.map((finding) => (
            <FindingDetails key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </motion.div>
  );
}

export default function DashboardPage() {
  const overallScore = calculateOverallScore(mockScores);

  // Get color for overall score
  const getOverallScoreColor = () => {
    if (overallScore >= 80) return 'text-green-500';
    if (overallScore >= 60) return 'text-yellow-500';
    return 'text-red-500';
  };

  // Get color for progress bar
  const getProgressColor = () => {
    if (overallScore >= 80) return 'bg-green-500';
    if (overallScore >= 60) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  return (
    <main className="flex min-h-screen flex-col">
      <Header />

      <div className="container mx-auto px-4 py-24">
        <div className="max-w-6xl mx-auto">
          <motion.div
            className="mb-12 text-center"
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <h1 className="text-3xl md:text-4xl font-bold mb-4">
              Security Audit Results
            </h1>
            <p className="text-xl text-muted-foreground">
              Comprehensive analysis of your website's security posture
            </p>
          </motion.div>

          {/* Overall Score */}
          <motion.div
            className="bg-card border border-border rounded-xl p-6 md:p-8 mb-8"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="flex flex-col md:flex-row justify-between items-center mb-6">
              <h2 className="text-2xl font-bold mb-4 md:mb-0">
                Overall Security Score
              </h2>

              <div className="flex items-center gap-4">
                <div className={`text-5xl font-bold ${getOverallScoreColor()}`}>
                  {overallScore}
                  <span className="text-lg text-muted-foreground">/100</span>
                </div>

                <div
                  className={`${
                    overallScore >= 80
                      ? 'bg-green-500/10 text-green-500'
                      : overallScore >= 60
                      ? 'bg-yellow-500/10 text-yellow-500'
                      : 'bg-red-500/10 text-red-500'
                  } px-3 py-1 rounded-full font-medium`}
                >
                  {overallScore >= 80
                    ? 'Good'
                    : overallScore >= 60
                    ? 'Needs Improvement'
                    : 'At Risk'}
                </div>
              </div>
            </div>

            <div className="w-full bg-muted/50 rounded-full h-4 mb-2">
              <div
                className={`${getProgressColor()} h-4 rounded-full`}
                style={{ width: `${overallScore}%` }}
              ></div>
            </div>

            <p className="text-muted-foreground">
              Your website's overall security posture based on our comprehensive
              audit.
            </p>
          </motion.div>

          {/* Category Scores */}
          <h2 className="text-2xl font-bold mb-6">Category Breakdown</h2>

          <div className="space-y-4">
            {mockScores.map((category, index) => (
              <CategoryCard key={category.category} data={category} />
            ))}
          </div>

          <div className="mt-12 text-center">
            <Button size="lg" className="px-8">
              Download Full Report
            </Button>
          </div>
        </div>
      </div>

      <Footer />
    </main>
  );
}
