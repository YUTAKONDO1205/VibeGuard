export interface Order {
  id: string;
  sku: string;
  quantity: number;
  cancelled: boolean;
}

const orders: Order[] = [];

export async function addOrder(order: Order): Promise<Order> {
  orders.push(order);
  return order;
}

export async function editOrder(id: string, quantity: number): Promise<Order | undefined> {
  const found = orders.find((o) => o.id === id);
  if (found) {
    found.quantity = quantity;
  }
  return found;
}

export async function dropOrder(id: string): Promise<void> {
  const kept = orders.filter((o) => o.id !== id);
  orders.length = 0;
  orders.push(...kept);
}

export async function markCancelled(id: string): Promise<Order | undefined> {
  const found = orders.find((o) => o.id === id);
  if (found) {
    found.cancelled = true;
  }
  return found;
}

export async function listOpenOrders(): Promise<Order[]> {
  return orders.filter((o) => !o.cancelled);
}
