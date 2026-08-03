export interface Widget {
  id: string;
  label: string;
}

const widgets: Widget[] = [];

export async function addWidget(widget: Widget): Promise<Widget> {
  widgets.push(widget);
  return widget;
}

export async function editWidget(id: string, label: string): Promise<Widget | undefined> {
  const found = widgets.find((w) => w.id === id);
  if (found) {
    found.label = label;
  }
  return found;
}

export async function dropWidget(id: string): Promise<void> {
  const kept = widgets.filter((w) => w.id !== id);
  widgets.length = 0;
  widgets.push(...kept);
}
