export type Severity = "Critical" | "High" | "Medium";
export type Difficulty = "Easy" | "Medium" | "Hard";

/** CTF framing for a risk: the NimbusMart scenario and its capturable flag. */
export interface Challenge {
  /** In-world briefing: what you've compromised and where you are. */
  scenario: string;
  /** The concrete goal - what to capture and prove. */
  objective: string;
  difficulty: Difficulty;
  points: number;
  /** Display hint for the flag shape, e.g. "FLAG{...}". */
  flagFormat: string;
  /** SHA-256 hex of the exact flag. The literal flag is never shipped. */
  flagHash: string;
  /** Progressive hints, revealed one at a time. */
  hints: string[];
}

export interface LabStep {
  /** Short imperative title, e.g. "Deploy the vulnerable workload" */
  title: string;
  /** One or two sentences explaining what this step does and why. */
  description: string;
  /** Shell/kubectl command the learner runs. Optional for pure-explanation steps. */
  command?: string;
  /** What the learner should expect to see after running the command. */
  expected?: string;
  /** "attack" = exploit step, "setup" = preparation, "fix" = remediation step. */
  kind: "setup" | "attack" | "fix" | "verify";
}

export interface Patch {
  /** e.g. "Drop all Linux capabilities" */
  title: string;
  /** Why this control matters. */
  description: string;
  /** The corrected YAML / config snippet. */
  code: string;
  lang?: string;
}

export interface Reference {
  label: string;
  url: string;
}

export interface Risk {
  /** OWASP id, e.g. "K01" */
  id: string;
  /** True for the retired-from-the-list "bonus" challenge (Supply Chain). */
  bonus?: boolean;
  /** URL slug, e.g. "insecure-workload-configurations" */
  slug: string;
  title: string;
  severity: Severity;
  /** One-line hook shown on the card. */
  tagline: string;
  /** Emoji or short icon shown on the card. */
  icon: string;

  /** 2-4 paragraph plain-language explanation. */
  overview: string[];
  /** Concrete business/technical impact bullets. */
  impact: string[];
  /** How the misconfiguration typically arises. */
  rootCauses: string[];

  attackScenario: {
    summary: string;
    /** Ordered narrative of how an attacker abuses it. */
    steps: string[];
  };

  /** CTF scenario + flag for this risk. */
  challenge: Challenge;

  lab: {
    objective: string;
    prerequisites: string[];
    /** Optional seed manifest deployed before the lab (e.g. plants the flag). */
    setupManifest?: string;
    /** Relative path (from repo root) to the vulnerable manifest. */
    vulnerableManifest: string;
    /** Relative path to the hardened manifest. */
    fixedManifest: string;
    /** The spoiler walkthrough - full solution, shown collapsed in the UI. */
    steps: LabStep[];
  };

  defense: {
    summary: string;
    patches: Patch[];
    bestPractices: string[];
  };

  checker: {
    /** matches the Go check id, e.g. "k01" */
    checkId: string;
    whatItChecks: string;
    /** Human-readable pass criteria bullets. */
    passCriteria: string[];
  };

  references: Reference[];
}
