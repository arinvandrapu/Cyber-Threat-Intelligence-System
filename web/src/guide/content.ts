import type { Data } from "../types";
import { VIEWS } from "../components/ui";
import type { Section } from "./common";
import { start } from "./sections/start";
import { overview } from "./sections/overview";
import { kev } from "./sections/kev";
import { queue } from "./sections/queue";
import { threats } from "./sections/threats";
import { landscape } from "./sections/landscape";
import { weakness, attack } from "./sections/graphs";
import { indicators } from "./sections/indicators";
import { evaluation } from "./sections/evaluation";
import { concepts, dataSection } from "./sections/reference";

/** Guide sections in sidebar order: the tabs in nav order, between "Start here" and the reference sections. */
export function guideSections(data: Data): Section[] {
  const sections = [start, overview, kev, queue, threats, landscape, weakness, attack, indicators, evaluation, concepts, dataSection].map((b) => b(data));
  // every tab's "How to read this tab" link targets a section with its view id; a missing one
  // logs, which fails the browser smoke test
  for (const [id] of VIEWS) {
    if (id !== "guide" && !sections.some((s) => s.id === id && s.view === id)) console.error(`Guide: no section for view "${id}"`);
  }
  return sections;
}
