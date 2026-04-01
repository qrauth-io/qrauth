import type { MarkerEvent } from 'react-map-gl/maplibre';

import { useState, useCallback } from 'react';

// ----------------------------------------------------------------------

type UseMapMarkerPopupReturn<T> = {
  selectedItem: T | null;
  onOpenPopup: (event: MarkerEvent<MouseEvent>, item: T) => void;
  onClosePopup: () => void;
};

export function useMapMarkerPopup<T>(): UseMapMarkerPopupReturn<T> {
  const [selectedItem, setSelectedItem] = useState<T | null>(null);

  const handleOpenPopup = useCallback((event: MarkerEvent<MouseEvent>, item: T) => {
    event.originalEvent.stopPropagation();
    setSelectedItem(item);
  }, []);

  const handleClosePopup = useCallback(() => {
    setSelectedItem(null);
  }, []);

  return {
    selectedItem,
    onOpenPopup: handleOpenPopup,
    onClosePopup: handleClosePopup,
  };
}
