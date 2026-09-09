import {
  Activity,
  Bot,
  FileText,
  FlaskConical,
  Grid3x3,
  LayoutDashboard,
  Radar,
  ScrollText,
  Settings,
  ShieldAlert,
} from "lucide-react";

export interface NavItem {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  /** Short description used for the mobile drawer and tooltips. */
  hint: string;
}

export const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, hint: "Fleet-wide attacker overview" },
  { to: "/honeypots", label: "Honeypots", icon: Radar, hint: "Deployed sensors and health" },
  {
    to: "/sessions",
    label: "Attack Sessions",
    icon: Activity,
    hint: "Attacker sessions to triage",
  },
  { to: "/logs", label: "Log Explorer", icon: ScrollText, hint: "Raw honeypot event search" },
  { to: "/analysis", label: "AI Analysis", icon: Bot, hint: "LLM analysis runs and history" },
  {
    to: "/evaluation",
    label: "Realism Evaluation",
    icon: FlaskConical,
    hint: "How convincing the honeypot looks",
  },
  { to: "/mitre", label: "MITRE ATT&CK", icon: Grid3x3, hint: "Technique coverage matrix" },
  {
    to: "/threat-intel",
    label: "Threat Intelligence",
    icon: ShieldAlert,
    hint: "Extracted indicators",
  },
  { to: "/reports", label: "Reports", icon: FileText, hint: "Analyst-ready threat reports" },
  { to: "/settings", label: "Settings", icon: Settings, hint: "Backend and engine configuration" },
];
