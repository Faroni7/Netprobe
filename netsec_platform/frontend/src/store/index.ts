import { create } from 'zustand';
import type { 
  User, 
  ESSStatus, 
  CaptureStatus, 
  DashboardStats,
  SecurityFinding,
  NetworkFlow,
  SensitiveArtifact,
  Asset,
  InvestigationCase,
  TimelineEvent 
} from '@/types';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  login: (user: User) => void;
  logout: () => void;
}

interface CaptureState {
  status: CaptureStatus | null;
  essStatus: ESSStatus | null;
  setCaptureStatus: (status: CaptureStatus) => void;
  setESSStatus: (status: ESSStatus) => void;
  activateESS: () => void;
  recoverESS: () => void;
}

interface DataState {
  flows: NetworkFlow[];
  findings: SecurityFinding[];
  sensitiveArtifacts: SensitiveArtifact[];
  assets: Asset[];
  cases: InvestigationCase[];
  timeline: TimelineEvent[];
  dashboardStats: DashboardStats | null;
  setFlows: (flows: NetworkFlow[]) => void;
  setFindings: (findings: SecurityFinding[]) => void;
  setSensitiveArtifacts: (artifacts: SensitiveArtifact[]) => void;
  setAssets: (assets: Asset[]) => void;
  setCases: (cases: InvestigationCase[]) => void;
  setTimeline: (events: TimelineEvent[]) => void;
  setDashboardStats: (stats: DashboardStats) => void;
}

interface UIState {
  sidebarOpen: boolean;
  activePage: string;
  searchQuery: string;
  selectedFinding: SecurityFinding | null;
  selectedFlow: NetworkFlow | null;
  selectedEvidence: SensitiveArtifact | null;
  toggleSidebar: () => void;
  setActivePage: (page: string) => void;
  setSearchQuery: (query: string) => void;
  setSelectedFinding: (finding: SecurityFinding | null) => void;
  setSelectedFlow: (flow: NetworkFlow | null) => void;
  setSelectedEvidence: (evidence: SensitiveArtifact | null) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  login: (user) => set({ user, isAuthenticated: true }),
  logout: () => set({ user: null, isAuthenticated: false }),
}));

export const useCaptureStore = create<CaptureState>((set) => ({
  status: null,
  essStatus: null,
  setCaptureStatus: (status) => set({ status }),
  setESSStatus: (status) => set({ essStatus: status }),
  activateESS: () => set((state) => ({
    essStatus: state.essStatus ? { ...state.essStatus, state: 'ACTIVATING' } : null,
  })),
  recoverESS: () => set((state) => ({
    essStatus: state.essStatus ? { ...state.essStatus, state: 'READY' } : null,
  })),
}));

export const useDataStore = create<DataState>((set) => ({
  flows: [],
  findings: [],
  sensitiveArtifacts: [],
  assets: [],
  cases: [],
  timeline: [],
  dashboardStats: null,
  setFlows: (flows) => set({ flows }),
  setFindings: (findings) => set({ findings }),
  setSensitiveArtifacts: (artifacts) => set({ sensitiveArtifacts: artifacts }),
  setAssets: (assets) => set({ assets }),
  setCases: (cases) => set({ cases }),
  setTimeline: (events) => set({ timeline: events }),
  setDashboardStats: (stats) => set({ dashboardStats: stats }),
}));

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: true,
  activePage: 'dashboard',
  searchQuery: '',
  selectedFinding: null,
  selectedFlow: null,
  selectedEvidence: null,
  toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
  setActivePage: (page) => set({ activePage: page }),
  setSearchQuery: (query) => set({ searchQuery: query }),
  setSelectedFinding: (finding) => set({ selectedFinding: finding }),
  setSelectedFlow: (flow) => set({ selectedFlow: flow }),
  setSelectedEvidence: (evidence) => set({ selectedEvidence: evidence }),
}));
