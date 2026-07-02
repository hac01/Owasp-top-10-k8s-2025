"use client";

import { useState } from "react";

export interface Tab {
  id: string;
  label: string;
  icon: string;
  content: React.ReactNode;
}

export function Tabs({ tabs }: { tabs: Tab[] }) {
  const [active, setActive] = useState(tabs[0]?.id);

  return (
    <div>
      <div className="sticky top-[73px] z-30 -mx-1 flex gap-1 overflow-x-auto border-b border-slate-200 bg-white/85 px-1 py-2 backdrop-blur-md">
        {tabs.map((t) => {
          const isActive = t.id === active;
          return (
            <button
              key={t.id}
              onClick={() => setActive(t.id)}
              className={`flex items-center gap-2 whitespace-nowrap rounded-lg px-4 py-2 text-sm font-semibold transition ${
                isActive
                  ? "bg-brand-600 text-white shadow-soft"
                  : "text-slate-600 hover:bg-brand-50 hover:text-brand-700"
              }`}
            >
              <span aria-hidden>{t.icon}</span>
              {t.label}
            </button>
          );
        })}
      </div>
      <div className="py-8">
        {tabs.map((t) => (
          <div key={t.id} className={t.id === active ? "animate-fade-up" : "hidden"}>
            {t.content}
          </div>
        ))}
      </div>
    </div>
  );
}
