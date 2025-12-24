# Link Collector - Chrome Extension

## Overview
A Chrome extension that automatically collects all hyperlinks from websites you visit and saves them to a single text file. The extension runs in the background and detects links whenever you open or switch to a new tab.

## Current State
✅ Fully functional Chrome extension ready for installation and use
✅ Automatic link detection on tab switching
✅ Persistent link storage using Chrome's storage API
✅ User-friendly popup interface with statistics
✅ One-click download of collected links

## Recent Changes
**October 25, 2025**
- Initial extension created with Manifest V3
- Implemented background service worker with tab event listeners
- Created content script for link extraction
- Built popup UI with download, refresh, and clear functions
- Fixed critical bug: Service worker now properly persists links across restarts by loading from storage before merging new links
- Generated extension icons (16x16, 48x48, 128x128)
- Created comprehensive installation instructions
- **Updated popup UI**: Added scrollable link list showing all collected links
- **Added clickable links**: Users can now click any link in the popup to visit it in a new tab
- Popup width increased to 400px for better link display
- Added max-height scrolling container (300px) for link list

## Project Architecture

### Core Extension Files
- **manifest.json** - Extension configuration (Manifest V3)
  - Defines permissions: tabs, scripting, downloads, storage, activeTab
  - Specifies background service worker and content scripts
  - Configures popup and icons

- **background.js** - Background service worker
  - Listens for tab activation and update events
  - Manages link collection and storage
  - Handles download functionality
  - Fixed to properly load existing links from storage before merging (prevents data loss on service worker restarts)

- **content.js** - Content script injected into web pages
  - Extracts all `<a href>` links from the DOM
  - Filters out javascript:, mailto:, and tel: links
  - Sends links back to background script

- **popup.html & popup.js** - Extension popup UI
  - Displays link count and last update time
  - Provides buttons to download, refresh stats, and clear links
  - Shows success/error status messages

### Supporting Files
- **icon16.png, icon48.png, icon128.png** - Extension icons
- **index.html** - Installation and usage instructions (served by documentation server)
- **README.md** - Project documentation

## How It Works

1. **Tab Events**: Background worker monitors `chrome.tabs.onActivated` and `chrome.tabs.onUpdated`
2. **Link Extraction**: Content script is injected into each visited page to extract all `<a>` tags
3. **Storage**: Links are persisted to `chrome.storage.local` to survive service worker restarts
4. **Download**: User clicks "Download Links" to save all collected links as a timestamped text file

## Installation Instructions

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select this project folder
5. The extension will appear in your toolbar

## User Preferences
- Simple, automatic operation preferred
- Single continuous text file for all links
- No manual triggers required
- Clean, minimal UI

## Development Notes
- Uses Manifest V3 (latest Chrome extension standard)
- Service worker pattern requires careful state management
- All links stored in chrome.storage.local for persistence
- In-memory cache used for quick access but storage is source of truth

## Future Enhancements (Optional)
- Link deduplication to avoid repeated entries
- Export to CSV or JSON formats
- Domain filtering options
- Organized output with website headers
- Manual pause/resume controls

## Version
1.0.0
