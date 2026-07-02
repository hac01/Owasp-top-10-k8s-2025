import type { Risk } from "../types";
import { k01 } from "./k01";
import { k02 } from "./k02";
import { k03 } from "./k03";
import { k04 } from "./k04";
import { k05 } from "./k05";
import { k06 } from "./k06";
import { k07 } from "./k07";
import { k08 } from "./k08";
import { k09 } from "./k09";
import { k10 } from "./k10";
import { kbonus } from "./kbonus";

/** The OWASP Kubernetes Top 10 - 2025 edition. */
export const risks: Risk[] = [k01, k02, k03, k04, k05, k06, k07, k08, k09, k10];

/** Retired from the 2025 list but kept as an extra challenge. */
export const bonusRisks: Risk[] = [kbonus];

/** Everything with a detail page: the 10 plus the bonus. */
export const allRisks: Risk[] = [...risks, ...bonusRisks];

export function getRisk(slug: string): Risk | undefined {
  return allRisks.find((r) => r.slug === slug);
}
