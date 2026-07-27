"use client";

import { useState } from "react";

export function useInvestigation() {
  const [loading, setLoading] = useState(false);

  const investigate = async () => {
    setLoading(true);
    // Placeholder for future API call
    setLoading(false);
  };

  return { investigate, loading };
}
