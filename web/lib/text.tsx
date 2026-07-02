import React from "react";

/**
 * Renders a string with inline `code` spans (backtick-delimited) as styled
 * <code> elements. Keeps content authoring simple - no full markdown engine.
 */
export function InlineText({ children }: { children: string }): React.ReactElement {
  const parts = children.split(/(`[^`]+`)/g);
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith("`") && part.endsWith("`")) {
          return (
            <code
              key={i}
              className="rounded-md bg-brand-50 px-1.5 py-0.5 font-mono text-[0.85em] text-brand-700"
            >
              {part.slice(1, -1)}
            </code>
          );
        }
        return <React.Fragment key={i}>{part}</React.Fragment>;
      })}
    </>
  );
}
