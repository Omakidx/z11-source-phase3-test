import type { FaultMode } from "./z11-p18-fault";

const PAGE_ID = "fxpay00000p18";
const STABLE_TIME = "2026-11-01T00:00:00.000Z";
const COMPONENTS = [
  { id: "fxcomp000api0", name: "API", description: "Fixture payments API" },
  {
    id: "fxcomp000chk0",
    name: "Checkout",
    description: "Fixture checkout flow",
  },
  {
    id: "fxcomp000whk0",
    name: "Webhooks",
    description: "Fixture webhook delivery",
  },
] as const;

export function buildStatusSummary(mode: FaultMode, nowIso: string) {
  const outage = mode === "outage";
  const componentStatus = outage ? "major_outage" : "operational";
  const components = COMPONENTS.map((component, position) => ({
    id: component.id,
    name: component.name,
    status: componentStatus,
    created_at: STABLE_TIME,
    updated_at: outage ? nowIso : STABLE_TIME,
    position: position + 1,
    description: component.description,
    showcase: true,
    start_date: null,
    group_id: null,
    page_id: PAGE_ID,
    group: false,
    only_show_if_degraded: false,
  }));

  return {
    page: {
      id: PAGE_ID,
      name: "Fixture Payments (staging)",
      url: "https://fixture-payments.staging.z11.dev",
      time_zone: "Etc/UTC",
      updated_at: outage ? nowIso : STABLE_TIME,
    },
    status: outage
      ? { indicator: "critical", description: "Major System Outage" }
      : { indicator: "none", description: "All Systems Operational" },
    components,
    incidents: outage
      ? [
          {
            id: "fxinc0000000p18",
            name: "Fixture payments outage",
            status: "investigating",
            impact: "critical",
            created_at: STABLE_TIME,
            updated_at: nowIso,
            started_at: STABLE_TIME,
            shortlink: "https://stspg.io/fxinc0000000p18",
            components,
            incident_updates: [],
          },
        ]
      : [],
    scheduled_maintenances: [],
  };
}
