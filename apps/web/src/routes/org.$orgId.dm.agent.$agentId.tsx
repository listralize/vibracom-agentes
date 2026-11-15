import { isPaidReturn } from "@agenteschat/client/lib/billing";
import { setDraftFor } from "@agenteschat/client/lib/drafts";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { agentPanelSearch, threadSearch } from "@/lib/open-param";
import { DmPage } from "@/pages/DmPage";

/** Direct message with an agent (sidebar "Agentes"). */
export const Route = createFileRoute("/org/$orgId/dm/agent/$agentId")({
  // `?m=<message>` opens the DM at that message (a search hit); `?paid`: back from paying for the workspace (the hold
  // banner says the payment is being confirmed), where a new workspace opens its right hand's DM (ADR 0137); `?thread=`
  // is the one in its panel, `?agent=` the agent's page there instead.
  validateSearch: (
    search: Record<string, unknown>,
  ): { m?: string; paid?: true; texto?: string } & ReturnType<typeof threadSearch> &
    ReturnType<typeof agentPanelSearch> => ({
    ...threadSearch(search),
    ...agentPanelSearch(search),
    ...(typeof search.m === "string" && search.m ? { m: search.m } : {}),
    ...(isPaidReturn(search) ? { paid: true as const } : {}),
    // Fork vibracom: `?texto=` leaves a question for the person to review and send (shortcuts from vibracom-sistema).
    ...(typeof search.texto === "string" && search.texto.trim() ? { texto: search.texto.slice(0, 1500) } : {}),
  }),
  component: function AgentDm() {
    const { agentId } = Route.useParams();
    const { texto } = Route.useSearch();
    // Handed before the DM mounts: its composer reads it once, as ⌘K "Pedir a um agente" does. Never sent by itself.
    useState(() => {
      if (texto) setDraftFor(`agent:${agentId}`, texto);
      return null;
    });
    return <DmPage key={agentId} target={{ agentId }} focusMessageId={Route.useSearch().m} />;
  },
});
