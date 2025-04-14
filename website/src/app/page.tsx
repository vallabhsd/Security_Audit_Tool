import { Hero } from '@/components/hero';
import { Features } from '@/components/features';
import { Process } from '@/components/process';
import { CtaSection } from '@/components/cta';
import { Header } from '@/components/header';
import { Footer } from '@/components/footer';
import { Toaster } from '@/components/ui/sonner';

export default function Home() {
  return (
    <main>
      <Toaster position="top-center" />
      <Header />
      <Hero />
      <Features />
      <Process />
      <CtaSection />
      <Footer />
    </main>
  );
}
