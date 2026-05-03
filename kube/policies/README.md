# Campaign Policies
#
# One NullfieldPolicy per campaign scenario. Each file can be applied directly:
#
#   kubectl apply -f kube/policies/customer-support-bot.yaml -n camazotz
#
# Or via the feedback loop:
#
#   make campaign SCENARIO=customer-support-bot
#
# Policies are generated from mcpnuke scan findings and hand-tuned for each
# deployment persona. See docs/campaigns/ in agentic-sec for the full context.
